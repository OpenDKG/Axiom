// AxiomFilter — rules.json loader and watcher.
//
// The daemon writes rules.json atomically (temp file + rename). We watch the
// containing directory with a vnode DispatchSource (fires on the rename) and
// additionally poll the file's identity once per second as a safety net for
// cases the directory watch can miss (directory deleted/recreated, events
// coalesced). Either path triggers a reload that completes well inside the
// 1 s budget in the contract.
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
    private static let maxFileSize = 32 * 1024 * 1024

    private let directory: String
    private let path: String
    private let log = Logger(subsystem: FilterLog.subsystem, category: "rules")
    private let queue = DispatchQueue(label: "com.axiom.firewall.filter.rules", qos: .userInitiated)

    /// Current table, swapped atomically.
    private let current = OSAllocatedUnfairLock<RuleTable>(initialState: .empty)

    // Loader state (only touched on `queue`).
    private var dirSource: DispatchSourceFileSystemObject?
    private var pollTimer: DispatchSourceTimer?
    private var lastSignature: FileSignature?
    private var reloadScheduled = false

    /// Called on the loader queue after a new table has been installed.
    var onReload: ((RuleTable) -> Void)?

    init(directory: String = RuleStore.defaultDirectory) {
        self.directory = directory
        self.path = (directory as NSString).appendingPathComponent(RuleStore.fileName)
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
        let fd = open(directory, O_EVTONLY | O_CLOEXEC)
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
    private struct FileSignature: Equatable {
        let device: dev_t
        let inode: ino_t
        let size: off_t
        let mtimeSec: Int
        let mtimeNsec: Int
    }

    private func signature() -> FileSignature? {
        var st = stat()
        guard stat(path, &st) == 0 else { return nil }
        return FileSignature(device: st.st_dev, inode: st.st_ino, size: st.st_size,
                             mtimeSec: st.st_mtimespec.tv_sec, mtimeNsec: st.st_mtimespec.tv_nsec)
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
            let table = try load()
            current.withLock { $0 = table }
            log.notice("rules loaded (\(reason, privacy: .public)): generation \(table.generation) block=\(table.blockRules.count) allow=\(table.allowRules.count) skipped=\(table.warnings.count)")
            for warning in table.warnings {
                log.error("rules: \(warning, privacy: .public)")
            }
            onReload?(table)
        } catch {
            log.error("rules file rejected (\(reason, privacy: .public)): \(String(describing: error), privacy: .public); keeping generation \(self.snapshot().generation)")
        }
    }

    private func load() throws -> RuleTable {
        let url = URL(fileURLWithPath: path)
        let data: Data
        do {
            let attrs = try FileManager.default.attributesOfItem(atPath: path)
            if let size = attrs[.size] as? NSNumber, size.intValue > RuleStore.maxFileSize {
                throw RuleLoadError.unreadable("file larger than \(RuleStore.maxFileSize) bytes")
            }
            data = try Data(contentsOf: url)
        } catch let error as RuleLoadError {
            throw error
        } catch {
            throw RuleLoadError.unreadable(error.localizedDescription)
        }
        return try RuleTable.parse(data)
    }
}
