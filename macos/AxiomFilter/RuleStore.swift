// AxiomFilter — rules.json loader and watcher.
//
// The daemon writes rules.json atomically (temp file + rename). We watch the
// containing directory with a vnode DispatchSource (fires on the rename) and
// additionally poll the file's identity once per second as a safety net for
// cases the directory watch can miss (directory deleted/recreated, events
// coalesced). Either path triggers a reload that completes well inside the
// 1 s budget in the contract.
//
// File identity (review #11): the file is opened with O_NOFOLLOW|O_CLOEXEC and
// read from that descriptor after an fstat that requires a regular file owned
// by root that is neither group- nor world-writable. Anything else is rejected
// with a logged reason and the last good table stays in force.
//
// Loading never happens on the verdict path: the verdict path only takes an
// unfair lock long enough to copy one object reference (`snapshot()`).
// A missing or invalid file keeps the last good table; before the first good
// load the table is empty (allow everything: fail-open).

import Darwin
import Foundation
import os

final class RuleStore: @unchecked Sendable {
    static let defaultDirectory = "/Library/Application Support/Axiom/filter"
    static let fileName = "rules.json"
    /// Refuse absurdly large files instead of stalling the loader.
    static let maxFileSize = 32 * 1024 * 1024

    private let directory: String
    private let path: String
    /// Owner the rules file must have (root in production; tests use their own uid).
    private let requiredOwner: uid_t
    private let log = Logger(subsystem: FilterLog.subsystem, category: "rules")
    private let queue = DispatchQueue(label: "com.axiom.firewall.filter.rules", qos: .userInitiated)

    /// Current table, swapped atomically.
    private let current = OSAllocatedUnfairLock<RuleTable>(initialState: .empty)

    // Loader state (only touched on `queue`).
    private var dirSource: DispatchSourceFileSystemObject?
    private var pollTimer: DispatchSourceTimer?
    private var lastSignature: FileSignature?
    private var reloadScheduled = false
    /// Rejected rules already logged, as "id\u{0}reason" (review #15: log once, not per reload).
    private var loggedRejections: Set<String> = []
    private var loggedFileRejection: String?

    /// Called on the loader queue after a new table has been installed.
    var onReload: ((RuleTable) -> Void)?
    /// Called on the loader queue when the file was rejected as a whole (table unchanged).
    var onRejectedFile: ((String) -> Void)?

    init(directory: String = RuleStore.defaultDirectory, requiredOwner: uid_t = 0) {
        self.directory = directory
        self.path = (directory as NSString).appendingPathComponent(RuleStore.fileName)
        self.requiredOwner = requiredOwner
    }

    /// The active table. Cheap and safe to call from any thread.
    func snapshot() -> RuleTable { current.withLock { $0 } }

    /// Loads the file synchronously once, then starts watching.
    func start() {
        queue.sync {
            ensureDirectory()
            reloadIfChanged(reason: "start")
            armDirectoryWatch()
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + 1, repeating: 1, leeway: .milliseconds(100))
            timer.setEventHandler { [weak self] in
                guard let self else { return }
                if self.dirSource == nil { self.armDirectoryWatch() }
                self.reloadIfChanged(reason: "poll")
            }
            timer.resume()
            pollTimer = timer
        }
    }

    func stop() {
        queue.sync {
            pollTimer?.cancel()
            pollTimer = nil
            dirSource?.cancel()
            dirSource = nil
        }
    }

    // MARK: - Watching

    private func ensureDirectory() {
        // The extension runs as root; create the directory so the watch can attach
        // even before the daemon has written its first table.
        if !FileManager.default.fileExists(atPath: directory) {
            do {
                try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true,
                                                        attributes: [.posixPermissions: 0o755])
            } catch {
                log.error("cannot create \(self.directory, privacy: .public): \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    private func armDirectoryWatch() {
        let fd = Darwin.open(directory, O_EVTONLY | O_CLOEXEC)
        guard fd >= 0 else { return } // the poll timer retries
        let source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd,
                                                               eventMask: [.write, .rename, .delete, .link, .attrib],
                                                               queue: queue)
        source.setEventHandler { [weak self, unowned source] in
            guard let self else { return }
            let events = source.data
            if events.contains(.delete) || events.contains(.rename) {
                // The directory itself went away or moved: drop the watch, the poll timer re-arms it.
                source.cancel()
                self.dirSource = nil
            }
            self.scheduleReload()
        }
        source.setCancelHandler { close(fd) }
        source.resume()
        dirSource = source
    }

    /// Coalesces bursts of directory events (temp write + rename) into one reload.
    private func scheduleReload() {
        guard !reloadScheduled else { return }
        reloadScheduled = true
        queue.asyncAfter(deadline: .now() + .milliseconds(50)) { [weak self] in
            guard let self else { return }
            self.reloadScheduled = false
            self.reloadIfChanged(reason: "change")
        }
    }

    // MARK: - Loading

    /// Identity of the file on disk; a change of any field means "reload".
    /// Owner and mode are part of it so a chown/chmod is re-evaluated (and re-rejected).
    private struct FileSignature: Equatable {
        let device: dev_t
        let inode: ino_t
        let size: off_t
        let mtimeSec: Int
        let mtimeNsec: Int
        let uid: uid_t
        let mode: mode_t
    }

    private func signature() -> FileSignature? {
        var st = stat()
        guard lstat(path, &st) == 0 else { return nil }
        return FileSignature(device: st.st_dev, inode: st.st_ino, size: st.st_size,
                             mtimeSec: st.st_mtimespec.tv_sec, mtimeNsec: st.st_mtimespec.tv_nsec,
                             uid: st.st_uid, mode: st.st_mode)
    }

    private func reloadIfChanged(reason: String) {
        let sig = signature()
        guard sig != lastSignature else { return }
        lastSignature = sig

        guard sig != nil else {
            log.notice("rules file missing (\(reason, privacy: .public)); keeping generation \(self.snapshot().generation)")
            return
        }
        do {
            let table = try RuleStore.loadFile(path, requiredOwner: requiredOwner)
            current.withLock { $0 = table }
            loggedFileRejection = nil
            log.notice("rules loaded (\(reason, privacy: .public)): generation \(table.generation) block=\(table.blockRules.count) allow=\(table.allowRules.count) rejected=\(table.rejected.count)")
            for rule in table.rejected {
                // Log each (id, reason) once; the daemon learns about every reload through filter.rules.
                if loggedRejections.insert(rule.id + "\u{0}" + rule.reason).inserted {
                    log.error("rules: rule \(rule.id, privacy: .public) rejected: \(rule.reason, privacy: .public)")
                }
            }
            if table.rejected.isEmpty { loggedRejections.removeAll() }
            onReload?(table)
        } catch {
            let message = String(describing: error)
            if loggedFileRejection != message {
                loggedFileRejection = message
                log.error("rules file rejected (\(reason, privacy: .public)): \(message, privacy: .public); keeping generation \(self.snapshot().generation)")
            }
            onRejectedFile?(message)
        }
    }

    /// Opens, validates and parses a rules file (review #11). Shared with the unit tests.
    ///
    /// Rejects (throws `RuleLoadError.unreadable`) when the path is a symlink, not a regular
    /// file, not owned by `requiredOwner`, group- or world-writable, or too large.
    static func loadFile(_ path: String, requiredOwner: uid_t = 0) throws -> RuleTable {
        let fd = Darwin.open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else {
            let err = errno
            throw RuleLoadError.unreadable(err == ELOOP ? "is a symlink (O_NOFOLLOW)" : "open failed: \(String(cString: strerror(err)))")
        }
        defer { close(fd) }

        var st = stat()
        guard fstat(fd, &st) == 0 else {
            throw RuleLoadError.unreadable("fstat failed: \(String(cString: strerror(errno)))")
        }
        guard (st.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else {
            throw RuleLoadError.unreadable("not a regular file (mode \(String(st.st_mode, radix: 8)))")
        }
        guard st.st_uid == requiredOwner else {
            throw RuleLoadError.unreadable("owned by uid \(st.st_uid), expected uid \(requiredOwner)")
        }
        guard st.st_mode & 0o022 == 0 else {
            throw RuleLoadError.unreadable("group/world-writable (mode \(String(st.st_mode & 0o7777, radix: 8)))")
        }
        guard st.st_size <= off_t(maxFileSize) else {
            throw RuleLoadError.unreadable("file larger than \(maxFileSize) bytes")
        }

        // Read from the validated descriptor, never from the path again.
        var data = Data()
        data.reserveCapacity(Int(st.st_size))
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let n = read(fd, &buffer, buffer.count)
            if n > 0 {
                data.append(buffer, count: n)
                if data.count > maxFileSize { throw RuleLoadError.unreadable("file grew past \(maxFileSize) bytes") }
                continue
            }
            if n == 0 { break }
            if errno == EINTR { continue }
            throw RuleLoadError.unreadable("read failed: \(String(cString: strerror(errno)))")
        }
        return try RuleTable.parse(data)
    }
}
