// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Blackbox;

/// <summary>
/// Shared Python pre-tool command and tamper-protection helpers embedded across Axiom agent
/// lifecycle hooks so every supported host enforces consistent guard-tamper, protected-delete,
/// exfiltration, protected-launch, and escalation blocks prior to upstream hook evaluation.
/// </summary>
public static class AgentCommandGuard
{
    public const string PythonHelpers = """
        _MAX_SHELL_UNWRAP_DEPTH = 8
        _MAX_NESTED_COMMANDS = 512
        # Longer commands are not parsed. One command's nested readings share a work budget: every
        # character costs one unit, and every operator or bracket, which can start a segment,
        # a redirection or a level, costs more. Both limits fail closed.
        _MAX_COMMAND_LENGTH = 16000
        _MAX_SHELL_WORK = 128000
        _SHELL_OPERATORS = ";|&\n(){}`"
        _OPERATOR_WORK = 12
        _REDIRECTION_WORK = 24
        _POSIX_SHELLS = ("sh", "bash", "zsh", "dash", "ksh", "mksh", "fish")
        _POWERSHELLS = ("powershell", "pwsh")
        _POWERSHELL_CMDLET = (r"(?:add|clear|compress|convertfrom|convertto|copy|expand|export|foreach|format|get|import|"
                              r"invoke|join|measure|move|new|out|remove|rename|resolve|select|set|sort|split|start|"
                              r"stop|test|where|write)-[a-z]+")
        _CODE_INTERPRETERS = ("python", "python3", "node", "perl", "ruby")
        _SHELL_WRAPPERS = _POSIX_SHELLS + ("cmd",) + _POWERSHELLS + _CODE_INTERPRETERS
        # Stands for a command that was not inspected. _check_command_safety blocks on it.
        _UNINSPECTABLE_SEGMENT = "__axiom_uninspectable_nested_command__"
        # Commands that run another command: (short flags, short flags that take a value,
        # long flags, long flags that take a value, operands before the command).
        _COMMAND_PREFIXES = {
            "sudo": ("AbBEeHiKklNnPSsVv", "ugCDhpRrtTU",
                     ("askpass", "background", "bell", "edit", "help", "list", "login", "non-interactive",
                      "no-update", "preserve-env", "preserve-groups", "remove-timestamp", "reset-timestamp",
                      "set-home", "shell", "stdin", "validate", "version"),
                     ("chdir", "chroot", "close-from", "command-timeout", "group", "host", "other-user",
                      "prompt", "role", "type", "user"), 0),
            "doas": ("Lns", "aCu", (), (), 0),
            "env": ("0iv", "CSu", ("debug", "help", "ignore-environment", "null", "version"),
                    ("chdir", "split-string", "unset"), 0),
            "nice": ("0123456789", "n", ("help", "version"), ("adjustment",), 0),
            "nohup": ("", "", ("help", "version"), (), 0),
            "timeout": ("fpv", "ks", ("foreground", "help", "preserve-status", "verbose", "version"),
                        ("kill-after", "signal"), 1),
            "stdbuf": ("", "eio", ("help", "version"), ("error", "input", "output"), 0),
            "ionice": ("thV", "cnPpu", ("help", "ignore", "version"),
                       ("class", "classdata", "pgid", "pid", "uid"), 0),
            "chrt": ("abdfhimoRrvV", "DPT",
                     ("all-tasks", "batch", "deadline", "fifo", "help", "idle", "max", "other", "pid",
                      "reset-on-fork", "rr", "verbose", "version"),
                     ("sched-deadline", "sched-period", "sched-runtime"), 1),
            "taskset": ("achpV", "", ("all-tasks", "cpu-list", "help", "pid", "version"), (), 1),
            "command": ("pVv", "", (), (), 0),
            "builtin": ("", "", (), (), 0),
            "exec": ("cl", "a", (), (), 0),
            "time": ("apqvV", "fo", ("append", "help", "portability", "quiet", "verbose", "version"),
                     ("format", "output"), 0),
            "xargs": ("0oprtx", "adEILnPs",
                      ("exit", "help", "interactive", "no-run-if-empty", "null", "open-tty", "verbose", "version"),
                      ("arg-file", "delimiter", "eof", "max-args", "max-chars", "max-lines", "max-procs",
                       "process-slot-var", "replace"), 0),
        }

        # Further programs that run the command given after their options, in the layout of the table above,
        # with the long names as text. The lists follow each program's option parser or manual page. Any other
        # option leaves the command uninspectable: a value it takes could not be told apart from the command.
        _LAUNCHER_PREFIXES = {name: (flags, valued, frozenset(long_flags.split()),
                                     frozenset(long_valued.split()), operands)
                              for name, (flags, valued, long_flags, long_valued, operands) in {
            "setsid": ("cfhVw", "",
                "ctty fork help version wait",
                "", 0),
            "sshpass": ("ehvV", "dfpP",
                "",
                "", 0),
            "ssh-agent": ("cdDksTuUV", "aEOPt",
                "",
                "", 0),
            "unshare": ("cCfhimnprTuUV", "GlRSw",
                ("cgroup clear-env fork forward-signals help ipc keep-caps kill-child map-auto "
                 "map-current-user map-root-user map-subids mount mount-binfmt mount-proc net pid time "
                 "unchanged user uts version"),
                ("boottime load-interp map-group map-groups map-user map-users monotonic owner propagation "
                 "root setgid setgroups setuid wd whitelist-env"), 0),
            "nsenter": ("acCeFhimnprTuUVwWZ", "GNSt",
                ("all cgroup env follow-context help ipc join-cgroup keep-caps mount net no-fork pid "
                 "preserve-credentials root time user user-parent uts version wd wdns"),
                "net-socket setgid setuid target", 0),
            "chroot": ("", "",
                "help skip-chdir version",
                "groups userspec", 1),
            "xvfb-run": ("ahl", "efnpsw",
                "auto-servernum help listen-tcp",
                "auth-file error-file server-args server-num wait xauth-protocol", 0),
            "dbus-run-session": ("", "",
                "help version",
                "config-file dbus-daemon", 0),
            "systemd-run": ("dGhPqrRStTv", "CEHMpu",
                ("collect help ignore-failure no-ask-password no-block no-pager on-clock-change "
                 "on-timezone-change pipe pty pty-late quiet remain-after-exit same-dir same-root-dir scope "
                 "send-sighup shell slice-inherit system user verbose version wait"),
                ("background capsule description expand-environment gid host job-mode json machine nice "
                 "on-active on-boot on-calendar on-startup on-unit-active on-unit-inactive output "
                 "path-property property root-directory service-type setenv slice socket-property "
                 "timer-property uid unit working-directory"), 0),
            "pkexec": ("", "u",
                "disable-internal-agent help keep-cwd version",
                "user", 0),
            "strace": ("AcCdDfFhiknNqrtTvVwxyYzZ", "abeEIoOpPsSuUX",
                ("absolute-timestamps always-show-pid arg-names daemonised daemonize daemonized debug "
                 "decode-fds failed-only failing-only follow-forks help hyperlink instruction-pointer "
                 "kill-on-exit namespace no-abbrev output-append-mode output-separately pidns-translation "
                 "quiet relative-timestamps seccomp-bpf secontext silence silent stack-trace stack-traces "
                 "strings-in-hex successful-only summary summary-only summary-wall-clock syscall-number "
                 "syscall-times timestamps tips version"),
                ("abbrev argv0 attach color columns const-print-style decode-pids detach-on env fault inject "
                 "interruptible kvm output raw read signal signals stack-trace-frame-limit status string-limit "
                 "summary-columns summary-sort-by summary-syscall-overhead syscall-limit trace trace-fds "
                 "trace-path user verbose write"), 0),
            "ltrace": ("bcCfhiLrStTV", "aADeFlnopsuwx",
                "demangle help no-signals version",
                "align config debug indent library max-depth output where", 0),
            "valgrind": ("dhqsv", "",
                ("D1 I1 LL alignment alloc-fn allow-mismatched-debuginfo aspace-minaddr "
                 "avg-transtab-entry-size basic-counts bb-out-file branch-sim cache-sim cachegrind-out-file "
                 "callgrind-out-file check-stack-refs check-stack-var child-silent-after-fork collect-atstart "
                 "collect-bus collect-jumps collect-state collect-systime combine-dumps compress-pos "
                 "compress-strings conflict-cache-size debuginfo-server delta-stacktrace demangle depth "
                 "detailed-counts detailed-freq dsymutil dump-after dump-before dump-every-bb dump-instr "
                 "dump-line error-exitcode error-limit error-markers errors-for-leak-kinds exclusive-threshold "
                 "exit-on-first-error expensive-definedness-checks extra-debuginfo-path fair-sched "
                 "first-race-only fnname free-fill free-is-write freelist-big-blocks freelist-vol "
                 "fullpath-after gen-suppressions heap heap-admin help-debug history-level ignore-fn "
                 "ignore-range-below-sp ignore-ranges ignore-thread-creation input-fd instr-atstart "
                 "instr-count-only interval-size join-list-vol keep-debuginfo keep-stacktraces kernel-variant "
                 "leak-check leak-check-heuristics leak-resolution log-fd log-file log-socket main-stacksize "
                 "malloc-fill massif-out-file max-snapshots max-stackframe max-threads merge-recursive-frames "
                 "num-callers num-transtab-sectors pages-as-heap partial-loads-ok pc-out-file peak-inaccuracy "
                 "progress-interval ptrace-addr quiet read-inline-info read-var-info redzone-size "
                 "report-signal-unlocked require-text-symbol run-cxx-freeres run-libc-freeres segment-merging "
                 "segment-merging-interval shared-threshold show-below-main show-confl-seg show-emwarns "
                 "show-error-list show-leak-kinds show-mismatched-frees show-possibly-lost show-reachable "
                 "show-stack-usage sigill-diagnostics sim-hints smc-check soname-synonyms stacks suppressions "
                 "threshold time-stamp time-unit toggle-collect tool trace-addr trace-alloc trace-barrier "
                 "trace-children trace-children-skip trace-children-skip-by-arg trace-cond trace-fork-join "
                 "trace-hb trace-mem trace-mutex trace-rwlock trace-semaphore trace-superblocks track-fds "
                 "track-lockorders track-origins undef-value-errors unw-stack-scan-frames "
                 "unw-stack-scan-thresh valgrind-stacksize verbose version vgdb vgdb-error vgdb-poll "
                 "vgdb-prefix vgdb-shadow-registers vgdb-stop-at workaround-gcc296-bugs xml xml-fd xml-file "
                 "xml-socket xml-user-comment xtree-leak xtree-leak-file xtree-memory xtree-memory-file "
                 "zero-before"),
                "", 0),
            "faketime": ("fhmv?", "p",
                "disable-shm exclude-monotonic freeze help version",
                "date-prog", 1),
            "fakeroot": ("huv", "bfils",
                "help unknown-is-real version",
                "faked fd-base lib", 0),
            "proot": ("0hlnV", "bikmpPqrRSvw",
                "about help kill-on-exit link2symlink mixed-mode netcoop root-id usage version",
                "bind change-id cwd kernel-release mount port pwd qemu rootfs verbose", 0),
            "firejail": ("c?", "",
                ("allow-debuggers allusers apparmor apparmor.print appimage bandwidth bind blacklist build "
                 "caps caps.drop caps.keep caps.print cat chroot cpu cpu.print dbus-log dbus-system "
                 "dbus-system.broadcast dbus-system.call dbus-system.log dbus-system.own dbus-system.see "
                 "dbus-system.talk dbus-user dbus-user.broadcast dbus-user.call dbus-user.log dbus-user.own "
                 "dbus-user.see dbus-user.talk debug debug-blacklists debug-caps debug-errnos "
                 "debug-private-lib debug-protocols debug-syscalls debug-syscalls32 debug-whitelists defaultgw "
                 "deterministic-exit-code deterministic-shutdown disable-mnt dns dns.print dnstrace env "
                 "fs.print get help hostname hosts-file icmptrace ids-check ids-init ignore include interface "
                 "ip ip6 ipc-namespace iprange join join-filesystem join-network join-or-start "
                 "keep-config-pulse keep-dev-shm keep-fd keep-var-tmp list ls mac machine-id "
                 "memory-deny-write-execute mkdir mkfile mtu name net net.print netfilter netfilter.print "
                 "netfilter6 netfilter6.print netlock netmask netns netstats nettrace nice no-remote no3d "
                 "noautopulse noblacklist nodbus nodvd noexec nogroups noinput nonewprivs noprinters noprofile "
                 "noroot nosound notv nou2f novideo nowhitelist oom output output-stderr overlay private "
                 "private-bin private-cache private-cwd private-dev private-etc private-home private-lib "
                 "private-opt private-srv private-tmp profile profile.print protocol protocol.print put quiet "
                 "read-only read-write restrict-namespaces rlimit-as rlimit-cpu rlimit-fsize rlimit-nofile "
                 "rlimit-nproc rlimit-sigpending rmenv scan seccomp seccomp-error-action "
                 "seccomp.block-secondary seccomp.drop seccomp.keep seccomp.print shutdown snitrace tab "
                 "timeout tmpfs top trace tracelog tree version veth-name whitelist writable-etc "
                 "writable-run-user writable-var writable-var-log x11 xephyr-screen"),
                "", 0),
            "catchsegv": ("", "",
                "help version",
                "", 0),
            "eatmydata": ("", "",
                "",
                "", 0),
            "torsocks": ("dhiq", "aPpu",
                "debug help isolate quiet shell version",
                "address pass port user", 0),
            "proxychains": ("qv", "f",
                "help",
                "", 0),
            "proxychains4": ("q", "f",
                "help",
                "", 0),
            "tsocks": ("?fhnosw", "",
                "",
                "", 0),
            "daemonize": ("av", "ceElopu",
                "",
                "", 0),
            "busybox": ("", "",
                "help install list list-full",
                "", 0),
            "chronic": ("ev", "",
                "",
                "", 0),
            "numactl": ("abdDHlstTuV", "cCfiILmMNopPSw",
                ("all balancing cpu-compress dump dump-nodes hardware help huge localalloc show strict touch "
                 "verify version"),
                ("cpubind cpunodebind file interleave length membind offset physcpubind preferred "
                 "preferred-many shm shmid shmmode weighted-interleave"), 0),
            "setpriv": ("dhV", "",
                ("clear-groups dump help init-groups keep-groups landlock-support list-caps "
                 "list-landlock-access nnp no-new-privs reset-env version"),
                ("ambient-caps apparmor-profile bounding-set egid euid groups inh-caps landlock-access "
                 "landlock-rule list-landlock-rights pdeathsig ptracer regid reuid rgid ruid seccomp-filter "
                 "securebits selinux-label"), 0),
            "prlimit": ("cdefhilmnqrstuvVxy", "op",
                ("as core cpu data fsize help locks memlock msgqueue nice noheadings nofile nproc raw rss "
                 "rtprio rttime sigpending stack verbose version"),
                "output pid", 0),
            "runcon": ("c", "lrtu",
                "compute help version",
                "range role type user", 0),
            "flock": ("eFhnosuVx?", "cEw",
                "close exclusive help nb no-fork nonblock nonblocking shared unlock verbose version",
                "command conflict-exit-code timeout wait", 0),
            "entr": ("acdnprsxz", "",
                "",
                "", 0),
            "script": ("adefFhkpqrtV", "BcEImoOT",
                "append flush force help quiet return timing version",
                "command echo log-in log-io log-out log-timing logging-format output-limit", 0),
            "start-stop-daemon": ("bCHKmoqStTvV", "acdgIkNnOPprRsux",
                ("background help make-pidfile no-close notify-await oknodo quiet remove-pidfile start status "
                 "stop test verbose version"),
                ("chdir chroot chuid exec group iosched name nicelevel notify-timeout output pid pidfile ppid "
                 "procsched retry signal startas umask user"), 0),
            "parallel": ("0MTVXYghkmopqrtuvx", "BCDEHIJLNPSUWadjns",
                ("bar bg bibtex cat cf citation cleanup color color-fail color-failed colorfail colorfailed "
                 "colour colour-fail colour-failed colourfail colourfailed compress controlmaster csv ctag "
                 "ctrl-c ctrlc dr dry-run dryrun embed eta exit fast fg fifo files files0 filter-host "
                 "filter-hosts filterhosts gnu group hashbang help hgrp hostgroup hostgroups hostgrp "
                 "interactive keep-order keeporder latest-line latestline lb line-buffer line-buffered "
                 "linebuffer linebuffered link ll max-line-length-allowed maxlinelengthallowed nn no-ctrl-c "
                 "no-ctrlc no-k no-keep-order no-notice no-run-if-empty noctrlc nok nokeeporder nonall "
                 "nonotice norunifempty noswap null number-of-cores number-of-cpus number-of-sockets "
                 "number-of-threads numberofcores numberofcpus numberofsockets numberofthreads onall open-tty "
                 "output-as-files output-as-files0 outputasfiles outputasfiles0 pipe pipe-part pipepart plain "
                 "plus progress quote record-env recordenv regex regexp remove-rec-sep removerecsep resume "
                 "resume-failed resumefailed retry-failed retryfailed round round-robin roundrobin rrs "
                 "semaphore session shebang shell-quote shell_quote shellquote show-limits showlimits shuf "
                 "silent skip-first-line skipfirstline spreadstdin tag tee tmux tmux-pane tmuxpane tollef "
                 "transfer tty ungroup unsafe use-cores-instead-of-threads use-cpus-instead-of-cores "
                 "use-sockets-instead-of-threads usecoresinsteadofthreads usecpusinsteadofcores "
                 "usesocketsinsteadofthreads verbose version wait will-cite willcite xapply xargs"),
                ("arg-file arg-file-sep arg-sep argfile argfilesep argsep basefile basenameextensionreplace "
                 "basenamereplace bf bin block block-size block-timeout blocksize blocktimeout bner bnr bt "
                 "col-sep colsep combine-exec combine-executable combineexec combineexecutable "
                 "compress-program compressprogram ctag-string ctagstring debug decompress-program "
                 "decompressprogram delay delimiter dirnamereplace dnr env er extensionreplace filter group-by "
                 "groupby halt halt-on-error haltonerror header id jl joblog jobs limit linkinputsource load "
                 "match max-args max-chars max-procs max-replace-args maxargs maxchars maxprocs maxreplaceargs "
                 "memfree memsuspend milestone min-version minversion ms nice parens process-slot-var "
                 "processslotvar profile recend recstart res result results retries return rpl rsync-opts "
                 "rsyncopts semaphore-name semaphore-timeout semaphorename semaphoretimeout seqreplace shard "
                 "shell-completion shellcompletion slf slotreplace sql sql-and-worker sql-master sql-worker "
                 "sqlandworker sqlmaster sqlworker ssh ssh-delay sshdelay sshlogin sshloginfile st tag-string "
                 "tagstring tempdir template term-seq termseq tf timeout tmpdir tmpl total total-jobs "
                 "totaljobs transfer-file transfer-files transferfile transferfiles trc trim "
                 "use-compress-program use-decompress-program usecompressprogram usedecompressprogram wd "
                 "work-dir workdir xapplyinputsource"), 0),
        }.items()}
        # Short options whose value, when there is one, is attached to them.
        _ATTACHED_VALUES = {"nsenter": "CimnprTuUwW", "prlimit": "cdefilmnqrstuvxy", "sshpass": "e", "script": "t"}
        # Options whose value is a user or group number; any other word there is not read.
        _NUMBER_VALUES = {"nsenter": ("G", "S", "setgid", "setuid")}
        # Options of these programs whose value is only read as a word of its own.
        _SEPARATE_VALUES = {"proxychains": "f", "proxychains4": "f"}
        # parallel options with an optional value.
        _PARALLEL_OPTIONAL = frozenset("e i l eof max-lines maxlines replace".split())
        # bwrap options and how many values each takes.
        _BWRAP_VALUES = {name: count for count, names in (
            (0, "as-pid-1 assert-userns-disabled clearenv die-with-parent disable-userns help level-prefix new-session "
                "not-a-security-boundary share-net unshare-all unshare-cgroup unshare-cgroup-try unshare-ipc "
                "unshare-net unshare-pid unshare-user unshare-user-try unshare-uts version"),
            (1, "add-seccomp-fd args argv0 block-fd cap-add cap-drop chdir dev dir exec-label file-label gid "
                "hostname info-fd json-status-fd lock-file mqueue overlay-src perms pidns proc remount-ro ro-overlay "
                "seccomp size sync-fd tmp-overlay tmpfs uid umask unsetenv userns userns-block-fd userns2"),
            (2, "bind bind-data bind-fd bind-try chmod dev-bind dev-bind-try file ro-bind ro-bind-data "
                "ro-bind-fd ro-bind-try setenv symlink"),
            (3, "overlay"),
        ) for name in names.split()}
        # gdb accepts each of these with one or two dashes. Only the options before --args matter.
        _GDB_FLAGS = frozenset(("batch batch-silent binary-output configuration enable-external-editor f fullname "
                                "help n nh no-escape-args nowindows nw nx q quiet r readnever readnow "
                                "return-child-result silent statistics tui version w windows write").split())
        _GDB_VALUED = frozenset(("D annotate b baud c cd command core d data-directory directory e "
                                 "early-init-command early-init-eval-command editor-command eiex eix eval-command ex "
                                 "exec i iex init-command init-eval-command interpreter ix l p pid s se symbols "
                                 "tclcommand tty ui x").split())
        # Programs whose own command does not simply follow their options.
        _SPECIAL_LAUNCHERS = ("bwrap", "entr", "flock", "gdb", "parallel", "runcon", "script", "start-stop-daemon")
        # These read the pipe as a list of arguments or files, not as input to the command they run.
        _LIST_READERS = ("xargs", "parallel", "entr")


        def _remembered(function):
            # Keeps recent results of a pure parsing helper: each check parses the same segments again.
            # Lists are handed out as copies. Bounded by entries and by the characters held.
            results = {}
            held = [0]

            def call(*key):
                result = results.get(key)
                if result is None:
                    if len(results) >= 4096 or held[0] > 500000:
                        results.clear()
                        held[0] = 0
                    held[0] += len(key[0] or "")
                    result = results[key] = function(*key)
                return list(result) if type(result) is list else result

            call.cache = results
            return call


        def _command_name(token: str) -> str:
            name = (token or "").lower().replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
            return name.removesuffix(".exe")


        def _launcher_options(name: str, words: list, idx: int) -> tuple:
            # Reads the options of a launcher from idx. Returns the index of the first other word, the
            # (name, value) pairs of the options that take a value, and False for an option that is not in the
            # launcher's table or whose value cannot be told apart from the command.
            flags, valued, long_flags, long_valued, _ = _LAUNCHER_PREFIXES[name]
            taken = []
            count = len(words)
            while idx < count:
                option = words[idx]
                if option == "--":
                    return idx + 1, taken, True
                if len(option) < 2 or not option.startswith("-"):
                    break
                idx += 1
                alone = ""  # an option with an optional value, written without it
                if option.startswith("--"):
                    key, equals, value = option[2:].partition("=")
                    if key in long_valued:
                        if not equals:
                            value = words[idx] if idx < count else ""
                            idx += 1
                        if key in _NUMBER_VALUES.get(name, ()) and not (value.isdigit() or value == "follow"):
                            return idx, taken, False
                        taken.append((key, value))
                    elif key in long_flags or (name == "parallel" and key in _PARALLEL_OPTIONAL):
                        alone = "" if equals else key
                    else:
                        return idx, taken, False
                else:
                    for position in range(1, len(option)):
                        char = option[position]
                        if char in valued:
                            value = option[position + 1:]
                            if value and char in _SEPARATE_VALUES.get(name, ""):
                                return idx, taken, False
                            if not value:
                                value = words[idx] if idx < count else ""
                                idx += 1
                            if char in _NUMBER_VALUES.get(name, ()) and not (value.isdigit() or value == "follow"):
                                return idx, taken, False
                            taken.append((char, value))
                            break
                        optional = name == "parallel" and char in _PARALLEL_OPTIONAL
                        if optional or char in _ATTACHED_VALUES.get(name, ""):
                            alone = char if position == len(option) - 1 else ""
                            break
                        if char not in flags:
                            return idx, taken, False
                following = words[idx] if idx < count else "-"
                if name == "prlimit" and alone and _looks_like_limit(following):
                    return idx, taken, False
                if name == "script" and alone in ("t", "timing") and following.replace(".", "", 1).isdigit():
                    idx += 1  # the BSD script takes a flush time here
                elif name == "parallel" and alone in _PARALLEL_OPTIONAL and not following.startswith("-"):
                    if alone not in ("l", "max-lines", "maxlines") or not following.isdigit():
                        return idx, taken, False
                    idx += 1
            return idx, taken, True


        def _looks_like_limit(word: str) -> bool:
            import re as _re
            return bool(_re.fullmatch(r"(?:\d+|unlimited)(?::(?:\d+|unlimited)?)?|:(?:\d+|unlimited)", word))


        def _special_launch(name: str, words: list, idx: int):
            # For a launcher whose options are not enough: (index of the command it runs, command texts it
            # hands to a shell, False when an option is unknown), or None when this call runs no command.
            count = len(words)
            if name == "gdb":
                end = next((position for position in range(idx, count) if words[position] in ("--args", "-args")), None)
                if end is None:
                    return None
                position = idx
                while position < end:
                    option, equals, _ = words[position].lstrip("-").partition("=")
                    if not words[position].startswith("-") or option not in _GDB_FLAGS | _GDB_VALUED:
                        return end + 1, [], False
                    position += 2 if option in _GDB_VALUED and not equals else 1
                return end + 1, [], position == end
            if name == "bwrap":
                while idx < count and words[idx].startswith("-"):
                    if words[idx] == "--":
                        return idx + 1, [], True
                    option = words[idx][2:] if words[idx].startswith("--") else ""
                    if option not in _BWRAP_VALUES:
                        return idx + 1, [], False
                    idx += 1 + _BWRAP_VALUES[option]
                return min(idx, count), [], True
            if name == "start-stop-daemon":
                # It names the program with --exec or --startas; its arguments follow --.
                try:
                    end = words.index("--", idx)
                except ValueError:
                    end = count
                own = words[idx:end]
                if any(word in ("--stop", "--status", "-K", "-T") for word in own):
                    return None
                programs = {}
                operands = []
                position = 0
                while position < len(own):
                    following, taken, known = _launcher_options(name, own, position)
                    if not known:
                        return idx + following, [], False
                    programs.update(taken)
                    operands.extend(own[following:following + 1])
                    position = following + 1
                # --startas wins over --exec, which then only identifies a running copy.
                program = next((programs[key] for key in ("a", "startas", "x", "exec") if programs.get(key)), "")
                if not program:
                    return None
                return count, [_join_words([program] + operands + words[end + 1:])], True
            if name == "script":
                # Options may follow the file name. -c gives the command; in the BSD form it follows the file.
                scripts = []
                operands = []
                while idx < count and len(operands) < 2:
                    idx, taken, known = _launcher_options(name, words, idx)
                    if not known:
                        return idx, scripts, False
                    scripts += [value for key, value in taken if key in ("c", "command")]
                    if idx < count:
                        if "<" not in words[idx] and ">" not in words[idx]:
                            operands.append(idx)
                        idx += 1
                if scripts:
                    return count, scripts, True
                return (operands[1] if len(operands) > 1 else count), [], True
            start = idx
            idx, taken, known = _launcher_options(name, words, idx)
            if not known:
                return idx, [], False
            if name == "runcon":
                # Without a context option, the first operand is the context.
                if not any(key in ("l", "r", "t", "u", "range", "role", "type", "user") for key, _ in taken) and not any(
                        word in ("-c", "--compute") for word in words[start:idx]):
                    idx += 1
                return min(idx, count), [], True
            if name == "flock":
                scripts = [value for key, value in taken if key in ("c", "command")]
                idx += 1  # the lock file or descriptor; after it only -c is an option
                if words[idx:idx + 1] in (["-c"], ["--command"]):
                    return count, scripts + words[idx + 1:idx + 2], True
                if idx < count and words[idx].startswith("--command="):
                    return count, scripts + [words[idx][10:]], True
                # flock reads no other option here, so one that stands in its place is not understood.
                known = not (idx < count and words[idx].startswith("-"))
                return (count if scripts else min(idx, count)), scripts, known
            if name == "entr":
                shell = any(word.startswith("-") and word != "--" and "s" in word for word in words[start:idx])
                if shell and idx < count:
                    return count, [words[idx]], True
                return idx, [], True
            # parallel
            if idx < count and words[idx] == ":::":
                # With no command of its own, each argument is a command. They are also read as one.
                arguments = [word for word in words[idx + 1:] if word not in (":::", "::::")]
                return count, arguments + ([" ".join(arguments)] if len(arguments) > 1 else []), True
            if idx < count and any(char.isspace() for char in words[idx]):
                return count, [words[idx]], True
            return idx, [], True
        def _strip_prefixes(tokens):
            # Skips assignments and commands such as sudo or timeout, with their options. Returns the
            # index of the real command, False for an option it does not know, and any command string
            # carried by an option (env -S).
            import re as _re
            idx = 0
            carried = []
            split = None
            spoken = None
            count = len(tokens)
            while idx < count:
                word, quoted = tokens[idx]
                if word == "&" or (not quoted and _re.match(r"[A-Za-z_][A-Za-z0-9_]*\+?=", word)):
                    idx += 1
                    continue
                name = _command_name(word)
                if name in _SPECIAL_LAUNCHERS:
                    spoken = spoken or [token for token, _ in tokens]
                    launched = _special_launch(name, spoken, idx + 1)
                    if launched is None:
                        break
                    idx, scripts, known = launched
                    carried.extend(scripts)
                    if not known:
                        return min(idx, count), False, carried
                    continue
                if name in _LAUNCHER_PREFIXES:
                    spoken = spoken or [token for token, _ in tokens]
                    idx, _, known = _launcher_options(name, spoken, idx + 1)
                    if not known:
                        return min(idx, count), False, carried
                    idx += _LAUNCHER_PREFIXES[name][4]
                    continue
                if name not in _COMMAND_PREFIXES:
                    break
                flags, valued, long_flags, long_valued, operands = _COMMAND_PREFIXES[name]
                idx += 1
                while idx < count:
                    option = tokens[idx][0]
                    if option == "--":
                        idx += 1
                        break
                    if name == "env" and option == "-":
                        idx += 1
                        continue
                    if not option.startswith("-") or option == "-":
                        break
                    idx += 1
                    if option.startswith("--"):
                        key, equals, value = option[2:].partition("=")
                        if key in long_valued:
                            if not equals:
                                value = tokens[idx][0] if idx < count else ""
                                idx += 1
                            if key == "split-string":
                                carried.append(value)
                                split = value
                        elif key not in long_flags:
                            return idx, False, carried
                        continue
                    for position in range(1, len(option)):
                        char = option[position]
                        if char in valued:
                            value = option[position + 1:]
                            if not value:
                                value = tokens[idx][0] if idx < count else ""
                                idx += 1
                            if name == "env" and char == "S":
                                carried.append(value)
                                split = value
                            break
                        if name == "xargs" and char in "eil":
                            break
                        if char not in flags:
                            return idx, False, carried
                idx += operands
                if split is not None and idx < count:
                    carried.append(split + " " + _join_words([token for token, _ in tokens[idx:]]))
                    split = None
            return min(idx, count), True, carried


        def _join_words(words) -> str:
            if len(words) == 1:
                return words[0]
            joined = []
            for word in words:
                if word and not any(ch.isspace() for ch in word):
                    joined.append(word)
                elif '"' in word:
                    joined.append("'" + word + "'")
                else:
                    joined.append('"' + word + '"')
            return " ".join(joined)


        def _decode_powershell(value: str):
            import base64 as _base64
            try:
                return _base64.b64decode((value or "").strip(), validate=True).decode("utf-16-le")
            except (ValueError, UnicodeDecodeError):
                return None


        def _wrapper_arguments(name: str, words):
            # The command strings an interpreter call carries, as (commands, parsed, index of the first
            # word of the command). parsed is False when a command is announced but cannot be read.
            import re as _re
            count = len(words)
            idx = 1
            if name in _POSIX_SHELLS:
                while idx < count:
                    word = words[idx]
                    if word.startswith("--command="):
                        return [word[10:]], True, idx
                    if word == "--command" or _re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", word):
                        after = idx + 1
                        if _re.fullmatch(r"-[A-Za-z]*[oO]", word):
                            after += 1
                        while after < count and len(words[after]) > 1 and words[after][0] in "-+":
                            after += 2 if _re.fullmatch(r"[-+][A-Za-z]*[oO]", words[after]) else 1
                        if after >= count:
                            return [], False, idx
                        return [words[after]], True, after
                    if _re.fullmatch(r"[-+][A-Za-z]*[oO]", word):
                        idx += 2
                    elif word != "--" and word[:1] in ("-", "+"):
                        idx += 1
                    else:
                        break
                return [], True, idx
            if name == "cmd":
                for idx in range(1, count):
                    flag = words[idx].lower()
                    if flag[:2] in ("/c", "/k", "/r"):
                        rest = ([words[idx][2:]] if len(flag) > 2 else []) + list(words[idx + 1:])
                        if not rest:
                            return [], False, idx
                        commands = [_join_words(rest)]
                        if len(rest) > 1 and any(ch.isspace() for ch in rest[0]):
                            commands.append(rest[0])
                        return commands, True, idx + 1
                return [], True, count
            if name in _POWERSHELLS:
                takes_value = ("executionpolicy", "windowstyle", "workingdirectory", "version", "inputformat",
                               "outputformat", "configurationname", "psconsolefile", "settingsfile",
                               "custompipename")
                while idx < count:
                    word = words[idx]
                    if not (word.startswith("-") and len(word) > 1):
                        return [_join_words(words[idx:])], True, idx
                    option, colon, value = word.lstrip("-").partition(":")
                    option = option.lower()
                    if option and "command".startswith(option):
                        rest = ([value] if value else []) + list(words[idx + 1:])
                        if not rest or rest == ["-"]:
                            return [], False, idx
                        return [_join_words(rest)], True, idx + 1
                    if option and (option == "ec" or "encodedcommand".startswith(option)):
                        encoded = value or (words[idx + 1] if idx + 1 < count else "")
                        decoded = _decode_powershell(encoded)
                        if not decoded:
                            return [], False, idx
                        return [decoded], True, idx + 1
                    if option and "file".startswith(option):
                        return [], True, idx
                    if option == "ep" or (option and any(full.startswith(option) for full in takes_value)):
                        idx += 1 if value else 2
                    else:
                        idx += 1
                return [], True, idx
            if name in ("python", "python3"):
                pattern = r"-[A-Za-z]*c"
            elif name == "node":
                pattern = r"-[pe]+|--eval|--print"
            elif name == "perl":
                pattern = r"-[A-Za-z]*[eE]"
            else:
                pattern = r"-[A-Za-z]*e"
            while idx < count:
                word = words[idx]
                if _re.fullmatch(pattern, word):
                    if idx + 1 >= count:
                        return [], False, idx
                    return [words[idx + 1]], True, idx + 1
                if name == "node" and word.startswith(("--eval=", "--print=")):
                    return [word.split("=", 1)[1]], True, idx
                if name.startswith("python") and word.startswith("-c") and len(word) > 2:
                    return [word[2:]], True, idx
                if word in ("-W", "-X"):
                    idx += 2
                elif word.startswith("-") and word != "-m":
                    idx += 1
                else:
                    break
            return [], True, idx


        @_remembered
        def _split_stages(raw: str, escapes: bool) -> list:
            # (piped, segment) pairs, split on unquoted ;, &&, ||, |, a single & and newlines. piped is
            # True when the segment reads the previous one's output. With escapes, a backslash also protects a
            # quote or operator, as in a POSIX shell; without, backslashes are plain (Windows paths).
            stages = []
            buf = []
            quote = ""
            piped = False
            i = 0
            n = len(raw)
            # Open ( that are outside quotes, True for $(. A single & inside $( ) or $(( )) does not end
            # the outer command; the substitution's own text is split when it is read as a command.
            opened = []
            substitutions = 0

            def close():
                segment = "".join(buf).strip()
                if segment:
                    stages.append((piped, segment))
                return bool(segment)

            while i < n:
                ch = raw[i]
                if escapes and ch == "\\" and quote != "'" and i + 1 < n:
                    if raw[i + 1] in ('"\\' if quote else "\"'\\;&|`$ "):
                        buf.append(raw[i:i + 2])
                        i += 2
                        continue
                if quote:
                    buf.append(ch)
                    if ch == quote:
                        quote = ""
                    i += 1
                    continue
                if ch in ("'", '"'):
                    quote = ch
                    buf.append(ch)
                    i += 1
                    continue
                if ch == "(":
                    opened.append(i > 0 and raw[i - 1] == "$")
                    substitutions += opened[-1]
                elif ch == ")" and opened:
                    substitutions -= opened.pop()
                if ch == "|" and buf and buf[-1] == ">":
                    buf.append(ch)  # >| is a redirection
                    i += 1
                    continue
                # A single & ends a command too, unless it is part of a redirection: &>, >&, <& (or |&).
                background = (ch == "&" and not substitutions and raw[i + 1:i + 2] != ">"
                              and (i == 0 or raw[i - 1] not in "<>|&"))
                if ch in "\n\r;|" or raw.startswith("&&", i) or background:
                    pipe = ch == "|" and not raw.startswith("||", i)
                    ended = close()
                    # A newline right after a pipe continues the pipeline.
                    piped = pipe or (piped and not ended and ch in "\n\r")
                    buf = []
                    i += 2 if raw.startswith(("&&", "||", "|&"), i) else 1
                    continue
                buf.append(ch)
                i += 1
            close()
            return stages


        def _split_operators(raw: str, escapes: bool) -> list:
            return [segment for _, segment in _split_stages(raw, escapes)]


        def _substitutions(raw: str, backticks: bool):
            # Bodies of $(...) and backtick substitutions outside single quotes, and False when one
            # is never closed.
            bodies = []
            quote = ""
            i = 0
            n = len(raw)
            while i < n:
                ch = raw[i]
                if quote == "'":
                    if ch == "'":
                        quote = ""
                    i += 1
                    continue
                if ch == "\\":
                    i += 2
                    continue
                if ch == '"':
                    quote = "" if quote else '"'
                elif ch == "'" and not quote:
                    quote = "'"
                elif raw.startswith("$(", i):
                    depth = 1
                    inner = ""
                    j = i + 2
                    while j < n:
                        current = raw[j]
                        if current == "\\" and inner != "'":
                            j += 2
                            continue
                        if inner:
                            if current == inner:
                                inner = ""
                        elif current in ("'", '"'):
                            inner = current
                        elif current == "(":
                            depth += 1
                        elif current == ")":
                            depth -= 1
                            if depth == 0:
                                break
                        j += 1
                    if depth:
                        return bodies, False
                    bodies.append(raw[i + 2:j])
                    i = j + 1
                    continue
                elif ch == "`" and backticks:
                    j = i + 1
                    while j < n and raw[j] != "`":
                        j += 2 if raw[j] == "\\" else 1
                    if j >= n:
                        return bodies, False
                    bodies.append(raw[i + 1:j].replace("\\`", "`"))
                    i = j + 1
                    continue
                i += 1
            return bodies, True


        def _unescape_unquoted(segment: str) -> str:
            # Removes the backslashes that a shell ignores outside quotes, keeping Windows paths and commands.
            import re as _re
            tokens = _tokenize_segment(segment)
            if "\\" not in segment or not tokens or _command_name(tokens[0][0]) in ("cmd",) + _POWERSHELLS:
                return segment
            out = []
            quote = ""
            word_start = 0
            i = 0
            n = len(segment)
            while i < n:
                ch = segment[i]
                if quote:
                    if ch == quote:
                        quote = ""
                elif ch in ("'", '"'):
                    quote = ch
                elif ch.isspace():
                    out.append(ch)
                    i += 1
                    word_start = len(out)
                    continue
                elif ch == "\\" and i + 1 < n:
                    word = "".join(out[word_start:word_start + 2])
                    if not _re.match(r"[A-Za-z]:|\\\\|%|\.\\|~\\|\\", word + (segment[i:i + 2] if not word else "")):
                        out.append(segment[i + 1])
                        i += 2
                        continue
                out.append(ch)
                i += 1
            return "".join(out)


        def _without_stray_closers(text: str) -> str:
            # Blanks the unquoted ) and } that close a group opened before this text.
            out = list(text)
            quote = ""
            opened = {"(": 0, "{": 0}
            i = 0
            while i < len(text):
                ch = text[i]
                if ch == "\\" and quote != "'":
                    i += 2
                    continue
                if quote:
                    if ch == quote:
                        quote = ""
                elif ch in ("'", '"'):
                    quote = ch
                elif ch in opened:
                    opened[ch] += 1
                elif ch in (")", "}"):
                    opener = "(" if ch == ")" else "{"
                    if opened[opener]:
                        opened[opener] -= 1
                    else:
                        out[i] = " "
                i += 1
            return "".join(out).strip()


        def _group_starts(segment: str) -> list:
            # Positions right after each unquoted { that stands before a space, as in f() { cmd.
            starts = []
            quote = ""
            i = 0
            while i < len(segment):
                ch = segment[i]
                if ch == "\\" and quote != "'":
                    i += 2
                    continue
                if quote:
                    if ch == quote:
                        quote = ""
                elif ch in ("'", '"'):
                    quote = ch
                elif ch == "{" and segment[i + 1:i + 2].isspace():
                    starts.append(i + 1)
                i += 1
            return starts


        @_remembered
        def _group_end(text: str, start: int, escapes: bool) -> int:
            # The index after the ) that closes the ( at start, or the length of an unclosed text.
            quote = ""
            depth = 0
            i = start
            while i < len(text):
                ch = text[i]
                if escapes and ch == "\\" and quote != "'":
                    i += 2
                    continue
                if quote:
                    if ch == quote:
                        quote = ""
                elif ch in ("'", '"'):
                    quote = ch
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if not depth:
                        return i + 1
                i += 1
            return len(text)


        def _word_end(text: str, start: int, escapes: bool) -> int:
            # The index after the shell word at start, keeping quotes and $( ) whole.
            quote = ""
            i = start
            while i < len(text):
                ch = text[i]
                if escapes and ch == "\\" and quote != "'":
                    i += 2
                    continue
                if quote:
                    if ch == quote:
                        quote = ""
                elif ch in ("'", '"', "`"):
                    quote = ch
                elif text.startswith(("$(", "<(", ">("), i):
                    i = _group_end(text, i + 1, escapes)
                    continue
                elif ch in " \t\r\n;|&<>()":
                    break
                i += 1
            return min(i, len(text))


        @_remembered
        def _redirections_apart(text: str, escapes: bool = True) -> str:
            # The same commands with each redirection moved, as its own words, to the end of its command.
            # A shell reads a redirection the same way wherever it stands. A command whose redirections
            # already stand alone after its words stays as written.
            # Quotes and substitutions stay as written too; their texts are read on their own.
            import re as _re
            if "<" not in text and ">" not in text:
                return text
            output = []
            command = []
            moved = []
            begin = 0
            misplaced = False
            # What may follow a redirection that already stands alone: the end of the command or another one.
            settled = _re.compile(r"(?:\d+|&)?[<>]|[;|&\n\r()]")

            def close(end):
                nonlocal misplaced
                if not misplaced:
                    output.append(text[begin:end])
                else:
                    words = "".join(command).rstrip()
                    output.append(" ".join(([words] if words else []) + moved))
                moved.clear()
                command.clear()
                misplaced = False

            quote = ""
            i = 0
            n = len(text)
            while i < n:
                ch = text[i]
                if escapes and ch == "\\" and quote != "'":
                    command.extend(text[i:i + 2])
                    i += 2
                    continue
                if quote:
                    command.append(ch)
                    if ch == quote:
                        quote = ""
                    i += 1
                    continue
                if ch in ("'", '"', "`"):
                    quote = ch
                    command.append(ch)
                    i += 1
                    continue
                if text.startswith(("$(", "<(", ">(", "(("), i):
                    end = _group_end(text, i if ch == "(" else i + 1, escapes)
                    command.extend(text[i:end])
                    i = end
                    continue
                redirection = (_re.compile(r"&>>?|<<<|<<-?|<>|<&|<|>>|>\||>&|>").match(text, i)
                               if ch in "<>&" else None)
                if not redirection:
                    if ch in ";|&\n\r()":
                        close(i)
                        output.append(ch)
                        begin = i + 1
                    else:
                        command.append(ch)
                    i += 1
                    continue
                operator = redirection.group()
                # A descriptor written right before it, such as 2, {name} or PowerShell's *, belongs to it.
                start = len(command)
                while start and len(command) - start < 32 and command[start - 1] not in " \t":
                    start -= 1
                before = "".join(command[start:])
                descriptor = ""
                if (operator[0] != "&" and (not start or command[start - 1] in " \t")
                        and _re.fullmatch(r"\d+|\*|\{[A-Za-z_]\w*\}", before)):
                    del command[start:]
                    descriptor = before if before.isdigit() else ""
                    misplaced = misplaced or not descriptor
                # Written against a word.
                misplaced = misplaced or bool(command) and command[-1] not in " \t"
                target_start = redirection.end()
                while target_start < n and text[target_start] in " \t":
                    target_start += 1
                i = _word_end(text, target_start, escapes)
                target = text[target_start:i]
                if not target:
                    command.extend(descriptor + operator)
                    i = max(i, redirection.end())
                    continue
                if operator == "<&" or (operator == ">&" and (descriptor or _re.fullmatch(r"\d+-?|-", target))):
                    moved.append(descriptor + operator + target)
                elif operator == ">&":
                    moved.append("&> " + target)
                elif operator == "<>":
                    moved.extend(["< " + target, "> " + target])
                else:
                    moved.append(descriptor + operator + " " + target)
                while command and command[-1] in " \t":
                    command.pop()
                while i < n and text[i] in " \t":
                    i += 1
                if command:
                    command.append(" ")
                # A word after the redirection means it does not stand after the words.
                misplaced = misplaced or i < n and not settled.match(text, i)
            close(n)
            return "".join(output)


        def _redirection_spellings(text: str) -> list:
            # The other spellings of a text with its redirections set apart, read with and without escapes.
            spellings = [_redirections_apart(text, True).strip()]
            if "\\" in text:
                spellings.append(_redirections_apart(text, False).strip())
            return [spelled for spelled in dict.fromkeys(spellings) if spelled and spelled != text]


        def _segment_spellings(segment: str) -> list:
            if segment.split(None, 1)[:1] in (["//"], ["///"], ["#"]):
                return []
            return _redirection_spellings(segment)


        def _bare_commands(segment: str) -> list:
            # The commands a segment holds behind then, do, else and similar words, ( and {.
            import re as _re
            openers = _re.compile(r"(?:\s|[({]|(?:then|do|else|elif|if|while|until|!)(?=[\s({]))*")
            cuts = [0] + (_group_starts(segment) if "{" in segment else [])
            found = []
            # Each piece between group braces, then the whole segment: a brace may also be a plain word.
            for start, end in list(zip(cuts, cuts[1:] + [len(segment)])) + [(0, len(segment))]:
                piece = segment[start:end].rstrip()
                if start != end and end != len(segment):
                    piece = piece.removesuffix("{")  # the brace that opens the next piece
                body = _without_stray_closers(piece[openers.match(piece).end():])
                if body and body != segment:
                    found.append(body)
            return list(dict.fromkeys(found))


        def _inner_commands(segment: str) -> list:
            # The bare commands of a segment, then the spellings of it and of them with their redirections
            # set apart. These are read in addition to the text as written.
            bare = _bare_commands(segment)
            found = list(bare)
            for text in [segment] + bare:
                for spelled in _segment_spellings(text):
                    found.append(spelled)
                    # Moved from the front of a command, a redirection can uncover another shell word.
                    found.extend(_bare_commands(spelled))
            return [candidate for candidate in dict.fromkeys(found) if candidate != segment]


        def _quotes_closed(segment: str) -> bool:
            # True when a POSIX shell would find every quote closed.
            quote = ""
            i = 0
            while i < len(segment):
                ch = segment[i]
                if ch == "\\" and quote != "'":
                    i += 2
                    continue
                if quote:
                    if ch == quote:
                        quote = ""
                elif ch in ("'", '"'):
                    quote = ch
                i += 1
            return not quote


        def _is_escaped_shell_call(segment: str) -> bool:
            # A POSIX shell call that escapes the quotes inside its argument. Reading its backslashes
            # as plain characters garbles it, so the POSIX reading decides what cannot be inspected.
            if not any(pair in segment for pair in ('\\"', "\\'", "\\\\")) or not _quotes_closed(segment):
                return False
            tokens = _tokenize_posix(segment)
            words = tokens[_strip_prefixes(tokens)[0]:]
            return bool(words) and _command_name(words[0][0]) in _POSIX_SHELLS + ("eval", "su", "runuser")


        def _reads_stdin_as_commands(command: str) -> bool:
            # True for a shell that runs what it reads from standard input.
            tokens = _tokenize_posix((_bare_commands(command) or [command])[0])
            words = [word for word, _ in tokens[_strip_prefixes(tokens)[0]:]]
            return (bool(words) and _command_name(words[0]) in _POSIX_SHELLS + ("su", "runuser")
                    and _reads_commands_from_stdin([words[0]] + _split_redirections(words[1:])[0]))


        def _matching_brackets(text: str) -> dict:
            # For each ( the index of the ) that matches it, counting brackets only.
            closes = {}
            open_at = []
            for index, char in enumerate(text):
                if char == "(":
                    open_at.append(index)
                elif char == ")" and open_at:
                    closes[open_at.pop()] = index
            return closes


        def _shell_reading(text: str, escapes: bool = True):
            # Reads a command's quoting as a POSIX shell does. Returns the command without comments and
            # here-documents, the here-document bodies that a shell runs, the bodies with an unquoted
            # delimiter, the text of a quote or here-document that is left open, or "", and the command
            # without the quoted here-documents inside a substitution that no shell runs.
            import re as _re
            heredoc = _re.compile(r"<<(-?)[ \t]*(?:'([^'\n]*)'|" + r'"([^"\n]*)"|(\\?)([A-Za-z_][\w.+-]*))'
                                  + r"(?![^\s;&|<>()`])")
            output = []
            runs, expanding, pending = [], [], []
            opened = []  # (what closes it, where it opened) for ( ), " and backticks
            command_start = 0
            command_reads, line_reads = {}, {}
            closes = None
            at_word = True
            unfinished = ""
            quoted_data = []  # (start, end) of quoted here-document bodies inside a substitution
            i = 0
            n = len(text)

            def emit(part):
                output.append(part)

            while i < n:
                ch = text[i]
                inside = opened[-1][0] if opened else ""
                if escapes and ch == "\\" and i + 1 < n:
                    emit(text[i:i + 2])
                    i += 2
                    at_word = False
                    continue
                if inside == '"':
                    if ch == '"':
                        opened.pop()
                    elif text.startswith("$(", i):
                        opened.append((")", i))
                        emit("$(")
                        i += 2
                        at_word, command_start = True, len(output)
                        continue
                    elif ch == "`":
                        opened.append(("`", i))
                        at_word, command_start = True, len(output) + 1
                        emit(ch)
                        i += 1
                        continue
                    emit(ch)
                    i += 1
                    at_word = False
                    continue
                if ch == "'" or text.startswith("$'", i):
                    ansi = ch == "$"
                    end = i + (2 if ansi else 1)
                    while end < n and text[end] != "'":
                        end += 2 if ansi and text[end] == "\\" else 1
                    if end >= n:
                        unfinished = text[i:]
                        emit(text[i:])
                        break
                    if ansi:
                        # This quoting form has its own backslash escapes.
                        body = _re.sub(r"\\(.)", lambda found: "" if found.group(1) in "'\"" else found.group(),
                                       text[i + 2:end], flags=_re.DOTALL)
                        emit("'" + body + "'")
                    else:
                        emit(text[i:end + 1])
                    i = end + 1
                    at_word = False
                    continue
                # cmd comment lines.
                batch = (ch in "rR:" and not inside and (not i or text[i - 1] == "\n")
                         and _re.compile(r"(?:rem(?=[ \t])|::)", _re.IGNORECASE).match(text, i))
                # PowerShell here-strings.
                block_string = ch == "@" and _re.compile(r"@(['" + r'"])[ \t]*\r?\n').match(text, i)
                if block_string:
                    end = text.find("\n" + block_string.group(1) + "@", block_string.end() - 1)
                    if end >= 0:
                        emit("''")
                        i = end + 3
                        at_word = False
                        continue
                if (ch == "#" and at_word) or batch:
                    while i < n and text[i] not in "\r\n" and not (inside == "`" and text[i] == "`"):
                        i += 1
                    continue
                if text.startswith("((", i):
                    # Arithmetic is kept as written.
                    if closes is None:
                        closes = _matching_brackets(text)
                    end = closes.get(i, -1) + 1
                    if end and text[end - 2:end] == "))":
                        emit(text[i:end])
                        i = end
                        at_word = False
                        continue
                if text.startswith("<<<", i):
                    emit("<<<")
                    i += 3
                    at_word = True
                    continue
                marker = heredoc.match(text, i) if ch == "<" else None
                if marker:
                    delimiter = next(group for group in marker.group(2, 3, 5) if group is not None)
                    # Further markers in one command or on one line share the answer of the first.
                    if command_start not in command_reads:
                        command_reads[command_start] = _reads_stdin_as_commands("".join(output[command_start:]))
                    line_end = text.find("\n", marker.end())
                    line_end = n if line_end < 0 else line_end
                    if line_end not in line_reads:
                        line_reads[line_end] = any(_reads_stdin_as_commands(stage) for piped, stage in
                                                   _split_stages(text[marker.end():line_end], True) if piped)
                    pending.append((delimiter, marker.group(1) == "-", marker.group(5) is None or bool(marker.group(4)),
                                    command_reads[command_start] or line_reads[line_end], i))
                    i = marker.end()
                    at_word = False
                    continue
                if ch == "\n" and pending:
                    emit(ch)
                    i += 1
                    for delimiter, tabs, quoted, run, start in pending:
                        body_start = i
                        lines = []
                        closed = False
                        while i < n and not closed:
                            end = text.find("\n", i)
                            end = n if end < 0 else end
                            line = text[i:end].rstrip("\r")
                            bare = line.lstrip("\t") if tabs else line
                            if bare == delimiter:
                                closed, body_end = True, i
                                i = end + 1
                            elif opened and opened[-1][0] == ")" and bare.startswith(delimiter) and bare[len(delimiter):].lstrip()[:1] == ")":
                                # The delimiter line can also close the enclosing substitution.
                                closed, body_end = True, i
                                i += len(line) - len(bare) + len(delimiter)
                            else:
                                lines.append(text[i:end])
                                i = end + 1
                        body = "\n".join(lines)
                        if not closed:
                            unfinished = unfinished or text[start:]
                        elif quoted and not run and any(closer == ")" for closer, _ in opened):
                            quoted_data.append((body_start, body_end))
                        if run:
                            runs.append(body)
                        if not quoted:
                            expanding.append(body)
                    pending = []
                    at_word, command_start = True, len(output)
                    continue
                closing = False
                if ch == '"':
                    opened.append(('"', i))
                elif ch == "`":
                    if inside == "`":
                        opened.pop()
                        closing = True
                    else:
                        opened.append(("`", i))
                elif ch == "(":
                    opened.append((")", i))
                elif ch == ")" and inside == ")":
                    opened.pop()
                emit(ch)
                i += 1
                # Where the next word can start.
                at_word = ch in " \t\r\n;&|(<>`" and not closing
                if ch in "\n;&|(`":
                    command_start = len(output)
            quotes = [where for closer, where in opened if closer != ")"]
            if quotes and not unfinished:
                unfinished = text[quotes[0]:]
            without_data = text
            for start, end in reversed(quoted_data):
                without_data = without_data[:start] + without_data[end:]
            return "".join(output), runs, expanding, unfinished, without_data


        def _expanded_substitutions(body: str):
            # The substitutions that a shell runs in a here-document with an unquoted delimiter, and False
            # when finding them would take more than the work budget.
            found = []
            work = 0
            i = 0
            while i < len(body):
                if body[i] == "\\":
                    i += 2
                    continue
                if body.startswith("$(", i):
                    end = _group_end(body, i + 1, True)
                    closed = end > i + 2 and body[end - 1] == ")"
                elif body[i] == "`":
                    end = i + 1
                    while end < len(body) and body[end] != "`":
                        end += 2 if body[end] == "\\" else 1
                    closed = end < len(body)
                    end += 1
                else:
                    i += 1
                    continue
                work += end - i
                if work > _MAX_SHELL_WORK:
                    return found, False
                if not closed:
                    i += 1
                    continue
                inner = body[i + 2:end - 1] if body[i] == "$" else body[i + 1:end - 1].replace("\\`", "`")
                found.append(inner)
                i = end
            return found, True


        def _runs_past_its_end(raw: str, unfinished: str) -> bool:
            # True when a POSIX reading is left open with more text to run.
            import re as _re
            if not _re.search(r"[\n;&|]", unfinished):
                return False
            # Windows paths use backslashes differently, so they are also read without escapes.
            windows = _re.search(r"[A-Za-z]:\\|%\w+%\\|\\\\[\w?.]", raw)
            return not (windows and not _shell_reading(raw, False)[3])


        def _collect_segments(command: str, depth: int, powershell: bool, found: list, code: list, seen: dict,
                              strict: bool = True, spent=None, lane: int = 0, foreign: bool = False) -> None:
            # A reading that is not strict still adds what it finds for the checks, but cannot by itself
            # report a command as uninspectable.
            import re as _re
            raw = command or ""
            key = (raw, powershell, strict)
            if not raw.strip() or seen.get(key, _MAX_SHELL_UNWRAP_DEPTH + 1) <= depth:
                return
            seen[key] = depth
            # The second reading of a command has a budget of its own.
            spent = [0, 0] if spent is None else spent
            spent[lane] += (len(raw) + _OPERATOR_WORK * sum(raw.count(char) for char in _SHELL_OPERATORS)
                            + _REDIRECTION_WORK * (raw.count("<") + raw.count(">")))
            if len(seen) > _MAX_NESTED_COMMANDS or spent[lane] > _MAX_SHELL_WORK:
                found.append(_UNINSPECTABLE_SEGMENT)
                return

            def lost(sure: bool = True) -> None:
                if strict and sure:
                    found.append(_UNINSPECTABLE_SEGMENT)

            def descend(inner: str, inner_powershell: bool, sure: bool = True, of_cmd=None) -> None:
                # Fail closed at the limit: nothing below it gets checked.
                if depth >= _MAX_SHELL_UNWRAP_DEPTH:
                    lost(sure)
                else:
                    _collect_segments(inner, depth + 1, inner_powershell, found, code, seen, strict and sure, spent, lane,
                                      foreign if of_cmd is None else of_cmd)

            first = _tokenize_segment(raw.lstrip()[:200])
            head = _command_name(first[0][0]) if first else ""
            # In PowerShell a backtick is an escape or a line continuation, not a substitution.
            in_powershell = powershell or head in _POWERSHELLS or bool(
                _re.fullmatch(_POWERSHELL_CMDLET, head))
            # The command is also read the way a POSIX shell reads its quoting; the checks see both readings.
            posix = not (foreign or in_powershell or head == "cmd")
            reading, run_bodies, expanding, unfinished, without_data = _shell_reading(raw)
            differs = " ".join(reading.split()) != " ".join(raw.split())
            if posix and _runs_past_its_end(raw, unfinished):
                lost()
            bodies, closed = _substitutions(raw, backticks=not in_powershell)
            unsure = []
            if posix and not closed and without_data != raw:
                # A quoted here-document holds plain data, so it does not leave a substitution open.
                known, closed = _substitutions(without_data, backticks=True)
                if closed:
                    unsure, bodies = [body for body in bodies if body not in known], known
            if not closed:
                lost()
            for body in unsure:
                descend(body, in_powershell, False)
            read = _substitutions(reading, backticks=True)[0] if differs and posix else bodies
            for body in bodies:
                descend(body, in_powershell, True, None if body in read else True)
            if differs:
                _collect_segments(reading, depth, powershell, found, code, seen, strict and posix, spent, 1, foreign)
            for body in run_bodies:
                descend(body, False, posix)
            for body in expanding:
                inners, complete = _expanded_substitutions(body)
                if not complete:
                    lost()
                for inner in dict.fromkeys(inners):
                    descend(inner, False, posix)

            # What each shell or interpreter that reads stdin is fed through a pipe. Pipelines are
            # read as a POSIX shell splits them.
            stages = _split_stages(raw, True)
            for position, (piped, segment) in enumerate(stages):
                if not piped or position == 0:
                    continue
                written = (_bare_commands(segment) or [segment])[0]
                reads = False
                for text in [written] + _redirection_spellings(written):
                    tokens = _tokenize_posix(text)
                    start = _strip_prefixes(tokens)[0]
                    # xargs takes the pipe, not the command it runs.
                    reads = reads or (not any(_command_name(word) in _LIST_READERS for word, _ in tokens[:start])
                                      and _reads_commands_from_stdin([word for word, _ in tokens[start:]]))
                if not reads:
                    continue
                before = _tokenize_posix(stages[position - 1][1])
                literal = _literal_output([word for word, _ in before[_strip_prefixes(before)[0]:]])
                if literal is None:
                    lost()
                    continue
                for text in dict.fromkeys([" ".join(literal)] + literal):
                    descend(text, False)

            # Both readings are inspected.
            posix_segments = [segment for _, segment in stages]
            shell_segments = set(posix_segments)
            # Each segment, then the bare commands inside it, which go through every check too.
            segments = {}
            for segment in dict.fromkeys(_split_operators(raw, False) + posix_segments):
                segments[segment] = None
                for bare in _inner_commands(segment):
                    segments[bare] = None
                    if segment in posix_segments:
                        shell_segments.add(bare)
            escaped = {segment for segment in segments if segment in shell_segments and _is_escaped_shell_call(segment)}
            for segment in segments:
                found.append(segment)
                plain = _unescape_unquoted(segment)
                if plain != segment:
                    found.append(plain)
                literal = _tokenize_segment(segment)
                readings = [literal]
                shell_like = _tokenize_posix(segment)
                if shell_like != literal:
                    readings.append(shell_like)
                for tokens in readings:
                    # Not sure: pieces cut out of an escaped shell argument, and its plain-backslash reading.
                    garbled = tokens is literal and len(readings) > 1 and segment in escaped
                    sure = (segment in shell_segments or not escaped) and not garbled
                    start, known, carried = _strip_prefixes(tokens)
                    if not known:
                        lost(sure)
                    for inner in carried:
                        descend(inner, in_powershell, sure)
                    words = [word for word, _ in tokens[start:]]
                    if not words:
                        continue
                    if start:
                        found.append(_join_words(words))
                    name = _command_name(words[0])
                    if name == "busybox" and len(words) > 1:
                        words = words[1:]
                        name = _command_name(words[0])
                        found.append(_join_words(words))
                    arguments, here = _split_redirections(words[1:])
                    if "<<<" in words[0]:
                        # bash<<<"..." with no space.
                        command_word, _, attached = words[0].partition("<<<")
                        name = _command_name(command_word)
                        here = attached or (arguments.pop(0) if arguments else "")
                        words = [command_word] + words[1:]
                    if here is not None and _reads_commands_from_stdin([words[0]] + arguments):
                        if "$" in here or "`" in here:
                            lost(sure)
                        else:
                            descend(here, False, sure)
                    if name in ("su", "runuser"):
                        argv, inner, parsed = _su_command(name, words)
                        if not parsed:
                            lost(sure)
                        if argv:
                            descend(_join_words(argv), False, sure)
                        if inner is not None:
                            descend(inner, False, sure)
                        continue
                    if name == "watch":
                        inner, parsed = _watched_command(words)
                        if not parsed:
                            lost(sure)
                        descend(inner, False, sure)
                        continue
                    if name == "find":
                        for argv in _find_exec_commands(words):
                            descend(_join_words(argv), False, sure)
                        continue
                    if name in ("eval", "source") or words[0] == ".":
                        if len(words) > 1:
                            descend(" ".join(words[1:]), False, sure)
                        continue
                    if name not in _SHELL_WRAPPERS:
                        continue
                    inners, parsed, position = _wrapper_arguments(name, words)
                    if not parsed:
                        lost(sure)
                    for inner in inners:
                        if name in _CODE_INTERPRETERS:
                            code.append(inner)
                        elif _re.match(r"\s*(?:\$\(|`|\$\{?[A-Za-z_]\w*\}?\s*$)", inner):
                            # The command itself is only known at run time.
                            lost(sure)
                        if tokens is literal and '\\"' not in segment and _nesting_is_lost(inner, words[position + 1:]):
                            lost(sure)
                        descend(inner, name in _POWERSHELLS, sure, name == "cmd")


        _expansions = {}


        def _split_redirections(words):
            # Separates redirections from arguments: (arguments, here-string word or None).
            import re as _re
            arguments = []
            here = None
            idx = 0
            while idx < len(words):
                word = words[idx]
                if "<" not in word and ">" not in word:
                    arguments.append(word)
                elif "<<<" in word:
                    before, _, after = word.partition("<<<")
                    if before and not before.isdigit():
                        arguments.append(before)
                    if not after:
                        idx += 1
                        after = words[idx] if idx < len(words) else ""
                    here = after
                elif _re.fullmatch(r"(?:\d*|&)(?:>>?\|?|<<?-?)", word):
                    idx += 1
                elif not _re.match(r"(?:\d*|&)[<>]", word):
                    arguments.append(word)
                idx += 1
            return arguments, here


        def _reads_commands_from_stdin(words) -> bool:
            # True for a shell or interpreter call that takes what it runs from standard input.
            import re as _re
            if not words:
                return False
            name = _command_name(words[0])
            arguments = _split_redirections(words[1:])[0]
            if name in ("su", "runuser"):
                _, command, parsed = _su_command(name, [words[0]] + arguments)
                return parsed and command is None
            if name not in _SHELL_WRAPPERS:
                return False
            if name == "cmd":
                return not any(word.lower()[:2] in ("/c", "/k", "/r") for word in arguments)
            idx = 0
            while idx < len(arguments):
                word = arguments[idx]
                lowered = word.lower()
                if name in _POSIX_SHELLS:
                    if word == "--command" or word.startswith("--command=") or _re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", word):
                        return False
                    if _re.fullmatch(r"-[A-Za-z]*s[A-Za-z]*", word):
                        return True
                    if _re.fullmatch(r"[-+][A-Za-z]*[oO]", word):
                        idx += 2
                        continue
                elif name in _POWERSHELLS:
                    option = lowered.lstrip("-").partition(":")[0]
                    if lowered.startswith("-") and option:
                        if "command".startswith(option):
                            return arguments[idx + 1:] == ["-"]
                        if option == "ec" or "encodedcommand".startswith(option) or "file".startswith(option):
                            return False
                        if option == "ep" or any(full.startswith(option) for full in ("executionpolicy", "windowstyle", "workingdirectory", "version")):
                            idx += 2
                            continue
                else:
                    if lowered in ("-c", "-m", "-e", "-p", "--eval", "--print", "--version", "-v", "--help", "-h"):
                        return False
                    if word in ("-W", "-X"):
                        idx += 2
                        continue
                if word == "-":
                    return True
                if not word.startswith(("-", "+")):
                    return False  # a script file
                idx += 1
            return True


        def _literal_output(words):
            # The literal arguments of echo or printf, or None when the text cannot be known.
            if not words or _command_name(words[0]) not in ("echo", "printf"):
                return None
            arguments = _split_redirections(words[1:])[0]
            while arguments and arguments[0] in ("-n", "-e", "-E", "--"):
                arguments = arguments[1:]
            if any("$" in word or "`" in word for word in arguments):
                return None
            return [word.replace("\\n", "\n").replace("\\t", " ") for word in arguments]


        def _su_command(name: str, words):
            # su and runuser: (direct argv or None, -c command or None, False for an unknown option).
            command = None
            user_named = False
            runuser_user = False
            idx = 1
            while idx < len(words):
                word = words[idx]
                if word == "--":
                    rest = words[idx + 1:]
                    if runuser_user and rest:
                        return rest, command, True
                    idx += 1
                    continue
                if word.startswith(("--command=", "--session-command=")):
                    command = word.split("=", 1)[1]
                elif word in ("--command", "--session-command") or (
                        word.startswith("-") and not word.startswith("--") and len(word) > 1 and word.endswith("c")
                        and all(ch in "flmpPc" for ch in word[1:])):
                    if idx + 1 >= len(words):
                        return None, None, False
                    command = words[idx + 1]
                    idx += 2
                    continue
                elif word in ("-s", "-g", "-G", "-w", "--shell", "--group", "--supp-group", "--whitelist-environment"):
                    idx += 2
                    continue
                elif word in ("-u", "--user") and name == "runuser":
                    runuser_user = True
                    idx += 2
                    continue
                elif word.startswith("--"):
                    if word.split("=", 1)[0] not in ("--login", "--preserve-environment", "--pty", "--fast", "--shell",
                                                     "--group", "--supp-group", "--user", "--whitelist-environment", "--help", "--version"):
                        return None, command, False
                    runuser_user = runuser_user or word.startswith("--user=")
                elif word.startswith("-"):
                    if any(ch not in "flmpPhV" for ch in word[1:]):
                        return None, command, False
                elif runuser_user:
                    return words[idx:], command, True
                elif not user_named:
                    user_named = True
                idx += 1
            return None, command, True


        def _watched_command(words):
            # watch [options] command: (the command string it runs, False for an unknown option).
            exact = False
            idx = 1
            while idx < len(words):
                word = words[idx]
                if word == "--":
                    idx += 1
                    break
                if word.startswith("--"):
                    key = word[2:].split("=", 1)[0]
                    if key == "interval":
                        idx += 1 if "=" in word else 2
                        continue
                    if key == "exec":
                        exact = True
                    elif key not in ("beep", "chgexit", "color", "differences", "errexit", "equexit", "no-linewrap",
                                     "no-rerun", "no-title", "no-wrap", "precise", "help", "version"):
                        return "", False
                    idx += 1
                    continue
                if not word.startswith("-") or word == "-":
                    break
                for position in range(1, len(word)):
                    char = word[position]
                    if char in "nq":
                        if position == len(word) - 1:
                            idx += 1
                        break
                    if char == "d":
                        break  # -d may carry an attached value
                    if char == "x":
                        exact = True
                    elif char not in "tgebcprwhv":
                        return "", False
                idx += 1
            rest = words[idx:]
            return (_join_words(rest) if exact and rest else " ".join(rest)), True


        def _find_exec_commands(words):
            # The argv of each find -exec, -execdir, -ok and -okdir action.
            commands = []
            idx = 1
            while idx < len(words):
                if words[idx] in ("-exec", "-execdir", "-ok", "-okdir"):
                    end = idx + 1
                    while end < len(words) and words[end] not in (";", "\\;", "+"):
                        end += 1
                    if end > idx + 1:
                        commands.append(words[idx + 1:end])
                    idx = end
                idx += 1
            return commands


        def _expand_command(command: str):
            # Every segment of a command and of the commands nested in it, inline interpreter code, and
            # the command texts themselves. Each check asks again, so recent results are kept.
            if len(command) > _MAX_COMMAND_LENGTH:
                return (_UNINSPECTABLE_SEGMENT,), (), ()
            cached = _expansions.get(command)
            if cached is None:
                found = []
                code = []
                seen = {}
                _collect_segments(command, 0, False, found, code, seen)
                if len(_expansions) >= 64:
                    _expansions.clear()
                scripts = dict.fromkeys(text for text, _, strict in seen if strict)
                cached = _expansions[command] = (tuple(dict.fromkeys(found)), tuple(code), tuple(scripts))
            return cached


        def _split_shell_segments(command: str, _depth: int = 0) -> list:
            if not _depth:
                return list(_expand_command(command or "")[0])
            found = []
            _collect_segments(command, _depth, False, found, [], {})
            return list(dict.fromkeys(found))


        def _nesting_is_lost(inner: str, rest) -> bool:
            # True when the argument to unwrap does not hold the whole command, so it cannot be inspected.
            def bare(token: str) -> str:
                return token.lower().strip("\\\"'^")

            words = inner.split()
            if not words or _command_name(bare(words[-1])) not in _POSIX_SHELLS + ("cmd",) + _POWERSHELLS + ("python", "python3"):
                return False
            return any(bare(token) in ("/c", "-c", "-command") for token in rest)


        @_remembered
        def _tokenize_posix(segment: str) -> list:
            # Like _tokenize_segment, reading backslashes as a POSIX shell does. A word that starts
            # like a Windows path keeps them.
            import re as _re
            tokens = []
            buf = []
            quote = ""
            had_quote = False
            in_tok = False
            text = segment or ""
            n = len(text)
            i = 0
            while i < n:
                ch = text[i]
                following = text[i + 1] if i + 1 < n else ""
                if ch == "\\" and quote != "'" and following:
                    if quote:
                        escapes = following in '"\\$`'
                    else:
                        escapes = not _re.match(r"[A-Za-z]:|\\\\|%|\.\\|~\\", "".join(buf[:2])) and not (not buf and following == "\\")
                    if escapes:
                        buf.append(following)
                        in_tok = True
                        i += 2
                        continue
                if quote:
                    if ch == quote:
                        quote = ""
                    else:
                        buf.append(ch)
                elif ch in ("'", '"'):
                    quote = ch
                    had_quote = True
                    in_tok = True
                elif ch.isspace():
                    if in_tok:
                        tokens.append(("".join(buf), had_quote))
                        buf = []
                        had_quote = False
                        in_tok = False
                else:
                    buf.append(ch)
                    in_tok = True
                i += 1
            if in_tok:
                tokens.append(("".join(buf), had_quote))
            return tokens


        @_remembered
        def _tokenize_segment(segment: str) -> list:
            return _scan_words(segment)


        def _scan_words(segment: str, start: int = 0, limit: int = 0) -> list:
            # Returns list of (token_text, was_quoted) preserving backslashes for Windows paths.
            # Reads from start and, with a limit, stops after that many tokens.
            tokens = []
            buf = []
            quote = ""
            had_quote = False
            in_tok = False
            text = segment or ""
            for index in range(start, len(text)):
                ch = text[index]
                if quote:
                    if ch == quote:
                        quote = ""
                    else:
                        buf.append(ch)
                    continue
                if ch in ("'", '"'):
                    quote = ch
                    had_quote = True
                    in_tok = True
                    continue
                if ch.isspace():
                    if in_tok:
                        tokens.append(("".join(buf), had_quote))
                        buf = []
                        had_quote = False
                        in_tok = False
                        if len(tokens) == limit:
                            break
                    continue
                buf.append(ch)
                in_tok = True
            if in_tok:
                tokens.append(("".join(buf), had_quote))
            return tokens


        @_remembered
        def _segment_verbs(segment: str) -> tuple:
            # Extract whole-word command names and two-word subcommands from unquoted structure.
            # Prevents substring false positives like "confirm " -> "rm " or "model " -> "del ".
            tokens = _tokenize_segment(segment)
            verbs = set()
            unquoted_words = []
            first_word = ""
            idx = _strip_prefixes(tokens)[0]
            if idx < len(tokens):
                head = os.path.basename(tokens[idx][0].lower())
                first_word = head
                verbs.add(head)
                verbs.add(head.removesuffix(".exe"))
                if idx + 1 < len(tokens) and not tokens[idx + 1][1]:
                    sub = tokens[idx + 1][0].lower()
                    verbs.add(f"{head.removesuffix('.exe')} {sub}")
                # Check for cmd /c <verb> style unquoted remainder
                if head.removesuffix(".exe") == "cmd":
                    for j in range(idx + 1, len(tokens) - 1):
                        if tokens[j][0].lower() in ("/c", "/k") and not tokens[j][1]:
                            nxt = os.path.basename(tokens[j + 1][0].lower())
                            verbs.add(nxt)
                            verbs.add(nxt.removesuffix(".exe"))
                            break
            for tok, quoted in tokens:
                if not quoted:
                    low = tok.lower()
                    unquoted_words.append(low)
                    for part in low.replace("(", " ").replace(")", " ").replace(".", " ").split():
                        unquoted_words.append(part)
            return first_word, verbs, set(unquoted_words)


        def _has_command_verb(command: str, verbs) -> bool:
            import re as _re
            targets = {v.strip().lower() for v in verbs if v.strip()}
            for seg in _split_shell_segments(command):
                first_word, cmd_verbs, unquoted_words = _segment_verbs(seg)
                low_seg = " ".join((seg or "").lower().split())
                unquoted_only = " ".join(w for w, q in _tokenize_segment(seg) if not q).lower()
                for target in targets:
                    if target == ">":
                        if _re.search(r"(?:^|[\s\d])>{1,2}\s*[^\s;&|]+", low_seg):
                            return True
                        continue
                    if " " in target:
                        if target in cmd_verbs:
                            return True
                        # Match unquoted multi-word invocation outside quoted strings
                        if _re.search(r"(?<![a-z0-9_-])" + _re.escape(target) + r"(?![a-z0-9_-])", unquoted_only):
                            return True
                    elif target.startswith(".") or target.endswith("("):
                        if target in low_seg:
                            return True
                    else:
                        if target in cmd_verbs:
                            return True
                        # Also catch inline function/cmdlet verbs in unquoted position or PowerShell subexpressions
                        if target in unquoted_words or _re.search(r"(?<![a-z0-9_-])" + _re.escape(target) + r"(?![a-z0-9_-])", unquoted_only):
                            return True
            return False


        def _has_redirection_to(command: str, markers) -> bool:
            import re as _re
            for seg in _split_shell_segments(command):
                norm_seg = seg.lower().replace("/", "\\")
                for m in _re.finditer(r"(?:^|[\s\d])>{1,2}\s*([^\s;&|]+)", norm_seg):
                    target = m.group(1).strip("\"'")
                    if any(marker in target for marker in markers):
                        return True
            return False


        def _tampers_with_guard(command: str) -> bool:
            # Match guard files and agent harness hook configs specifically (never arbitrary
            # project files that merely happen to be named hooks.json).
            norm = _normalize_command(command).replace("/", "\\")
            markers = (
                "plugins\\blackbox",
                "axiom-guard-bridge",
                "axiom-antigravity-hook",
                "axiom-claude-hook",
                "axiom-codex-hook",
                "axiom-cursor-hook",
                "axiom-windsurf-hook",
                "axiom-gemini-hook",
                "axiom-cline-hook",
                "axiom-copilot-hook",
                "axiom-deepseek-hook",
                "axiom-zcode-hook",
                ".claude\\hooks.json",
                ".claude\\settings",
                ".codex\\hooks.json",
                ".cursor\\hooks.json",
                ".gemini\\settings",
                ".windsurf\\hooks.json",
                ".github\\hooks\\",
                ".clinerules\\",
                "hermes\\blackbox",
                "axiom\\modules\\blackbox",
                "hermes\\config.yaml",
                ".zcode\\cli\\config.json",
                "blackbox\\agent-blackbox\\hooks.json",
            )
            if not any(marker in norm for marker in markers):
                return False
            if _has_redirection_to(command, [m.replace("\\", "/") for m in markers] + list(markers)):
                return True
            verbs = (
                "del", "erase", "rm", "rmdir", "mv", "move", "ren", "rename",
                "remove-item", "move-item", "rename-item", "copy-item",
                "set-content", "add-content", "out-file", "clear-content",
                "unlink", "copy", "cp", "icacls", "chmod", "chown",
                "shutil.rmtree", "os.remove", "os.unlink",
            )
            return _has_command_verb(command, verbs)


        def _disables_guard(command: str) -> bool:
            # Service/process/task management targeting Axiom/Blackbox, or delete/ACL verbs
            # targeting actual Axiom install/data/evidence locations (never repo checkouts or temp builds).
            norm = _normalize_command(command).replace("/", "\\")
            if not norm:
                return False
            if "auditpol /clear" in norm or "shadowcopy delete" in norm or "wmic shadowcopy" in norm:
                return True
            if _stops_guard_process(command):
                return True
            service_verbs = (
                "sc stop", "sc delete", "stop-service", "restart-service", "set-service",
                "net stop", "taskkill", "schtasks /change", "schtasks /delete",
                "disable-scheduledtask", "unregister-scheduledtask",
                "systemctl stop", "systemctl disable", "launchctl unload", "launchctl bootout",
            )
            service_targets = (
                "axiom.service", "axiom.desktop", "axiomd", "com.axiom.service",
                "agent blackbox", "axiom-blackbox", "blackbox",
            )
            if _has_command_verb(command, service_verbs):
                # Unwrap the command as written too: rewriting "/" breaks flags such as cmd /c.
                segments = _split_shell_segments(norm) + [
                    _normalize_command(seg).replace("/", "\\") for seg in _split_shell_segments(command)]
                unquoted = " ".join(w for seg in segments for w, q in _tokenize_segment(seg) if not q)
                words = set(unquoted.replace('"', " ").replace("'", " ").split())
                if "axiom" in words or any(t in unquoted for t in service_targets):
                    return True
            path_markers = (
                "appdata\\local\\axiom",
                "local\\axiom\\",
                ".local\\share\\axiom",
                "application support\\axiom",
                "programdata\\axiom",
                "program files\\axiom",
                "programs\\axiom",
                "axiom\\modules\\blackbox",
                "hermes\\blackbox",
                "plugins\\blackbox",
                "agent-evidence.jsonl",
                "guard-failure-policy.txt",
                "protection-status.json",
                "usr\\lib\\axiom-firewall",
                "usr\\libexec\\axiom",
                "var\\lib\\axiom",
                "etc\\axiom",
            )
            file_verbs = (
                "del", "erase", "rm", "rmdir", "remove-item", "unlink",
                "icacls", "chmod", "chown", "takeown",
            )
            return any(m in norm for m in path_markers) and _has_command_verb(command, file_verbs)


        @_remembered
        def _normalize_command(command: str) -> str:
            # Expands shell variables and Win32 path prefixes before any path check runs.
            text = (command or "").lower()
            home = os.path.normpath(str(Path.home())).lower()
            profile = (os.environ.get("USERPROFILE") or str(Path.home())).lower()
            replacements = {
                "$env:userprofile": profile,
                "%userprofile%": profile,
                "$env:localappdata": (os.environ.get("LOCALAPPDATA") or "").lower(),
                "%localappdata%": (os.environ.get("LOCALAPPDATA") or "").lower(),
                "$env:appdata": (os.environ.get("APPDATA") or "").lower(),
                "%appdata%": (os.environ.get("APPDATA") or "").lower(),
                "${home}": home,
                "$home": home,
                "%home%": home,
            }
            for key, value in replacements.items():
                if value:
                    text = text.replace(key, value)
            text = text.replace("\\\\?\\", "").replace("//?/", "").replace("\\\\.\\", "")
            text = text.replace("~/", home + "\\").replace("~\\", home + "\\")
            return " ".join(text.split())


        def _deletes_protected(command: str, protected) -> bool:
            verbs = ("del", "erase", "rm", "rmdir", "rd", "remove-item", "unlink",
                     "move", "move-item", "ren", "rename", "rename-item", "mv",
                     "shred", "truncate", "shutil.rmtree", "os.remove", "os.unlink")
            if _deletes_inline(command, protected):
                return True
            if not (_has_command_verb(command, verbs) or _has_delete_form(command)):
                return False
            return _hits_protected(command, protected)


        def _has_delete_form(command: str) -> bool:
            # find -delete, find -exec rm and rsync --delete remove files without a delete verb first.
            for segment in _split_shell_segments(command):
                tokens = _tokenize_posix(segment)
                words = [word for word, _ in tokens[_strip_prefixes(tokens)[0]:]]
                if not words:
                    continue
                name = _command_name(words[0])
                if name == "find" and ("-delete" in words or any(
                        flag in ("-exec", "-execdir", "-ok", "-okdir")
                        and _command_name(target) in ("rm", "rmdir", "unlink", "shred", "truncate")
                        for flag, target in zip(words, words[1:]))):
                    return True
                if name == "rsync" and any(word.startswith("--delete") or word == "--remove-source-files" for word in words):
                    return True
            return False


        def _deletes_inline(command: str, protected) -> bool:
            # Delete calls inside python, node, ruby or perl code passed on the command line.
            calls = ("rmtree(", "os.remove(", "os.rmdir(", "unlink(", "unlinksync(", "fs.rm", "rmsync(",
                     "rmdirsync(", "fileutils.rm", "file.delete(", "dir.delete(")
            return any(
                any(call in source.lower() for call in calls) and _text_hits_protected(source, protected)
                for source in _expand_command(command)[1])


        def _reads_protected(command: str, protected) -> bool:
            if _rsync_copies_protected(command, protected, to_other_host=False):
                return True
            verbs = ("cat", "type", "more", "head", "tail", "get-content", "readalltext",
                     "open(", ".read(", "copy", "cp", "get-item", "strings", "forfiles",
                     "findstr", "select-string", "grep", "rg", "tar", "compress-archive",
                     "copy-item", "move-item", "robocopy", "xcopy", "openssl", "ssh-keygen",
                     "gpg", "age", "makecab", "expand", "esentutl", "ssh -i", "split", "csplit", "base64")
            if not _has_command_verb(command, verbs):
                return False
            tokens = _protected_tokens(protected)
            for candidate in _inspected_texts(command):
                text = _normalize_command(candidate)
                words = text.replace("\\", " ").replace("/", " ").replace('"', " ").replace("'", " ").split()
                if _any_word_matches(words, tokens) or _glob_hits(text, tokens):
                    return True
            return False


        def _hidden_path_read(command: str, protected) -> bool:
            # The read check for paths written with a shell variable or a Win32 prefix. Other commands
            # keep the literal check, so that ordinary file names are not false positives.
            raw = (command or "").lower()
            hidden = ("$home", "%userprofile%", "$env:userprofile", "$env:localappdata",
                      "%localappdata%", "$env:appdata", "%appdata%", "~/", "~\\", "\\\\?\\", "//?/")
            if not any(marker in raw for marker in hidden):
                return False
            text = _normalize_command(raw)
            if not _hits_protected(text, protected):
                return False
            verbs = ("cat", "type", "more", "head", "tail", "get-content", "readalltext",
                     "open(", ".read(", "copy", "cp", "get-item", "strings", "forfiles")
            return _has_command_verb(command, verbs)


        def _redirection_targets(segment: str) -> list:
            # Words that unquoted output redirections (>, >>, >|, &>, 2>) write to.
            targets = []
            quote = ""
            i = 0
            n = len(segment)
            while i < n:
                ch = segment[i]
                if quote:
                    if quote == '"' and ch == "\\" and segment[i + 1:i + 2] in ('"', "\\"):
                        i += 2
                        continue
                    if ch == quote:
                        quote = ""
                elif ch in ("'", '"'):
                    quote = ch
                elif ch == "\\" and segment[i + 1:i + 2] in ('"', "'", ">"):
                    i += 2
                    continue
                elif ch == ">":
                    j = i + 1
                    while j < n and segment[j] in ">|":
                        j += 1
                    if segment[j:j + 1] != "&":
                        tokens = _scan_words(segment, j, 1)
                        if tokens:
                            targets.append(tokens[0][0])
                    i = j
                    continue
                i += 1
            return targets


        def _edited_in_place(name: str, arguments) -> list:
            # The files sed -i or perl -i rewrite; empty without an in-place flag. Without -e or -f the
            # first operand is the script.
            in_place = False
            scripted = False
            operands = []
            idx = 0
            while idx < len(arguments):
                word = arguments[idx]
                if name == "perl" and operands:
                    operands.append(word)  # everything after a perl script belongs to the script
                elif word == "--":
                    operands.extend(arguments[idx + 1:])
                    break
                elif word.startswith("--"):
                    option, equals, _ = word.partition("=")
                    in_place = in_place or option == "--in-place"
                    if option in ("--expression", "--file"):
                        scripted = True
                        idx += 0 if equals else 1
                elif word.startswith("-") and len(word) > 1:
                    for position in range(1, len(word)):
                        char = word[position]
                        if char == "i":
                            in_place = True  # the rest is the backup suffix
                            break
                        if char in ("eE" if name == "perl" else "ef"):
                            scripted = True
                            if position == len(word) - 1:
                                idx += 1
                            break
                        if name == "perl" and char in "IMm":
                            break
                else:
                    operands.append(word)
                idx += 1
            if not in_place:
                return []
            return operands if scripted else operands[1:]


        def _copy_operands(name: str, arguments) -> list:
            # The sources and destination of rsync or scp, without options and their values.
            short_valued = "efBTM" if name == "rsync" else "cDFiJloPSX"
            long_valued = ("--rsh", "--filter", "--exclude", "--include", "--exclude-from", "--include-from",
                           "--files-from", "--block-size", "--temp-dir", "--log-file", "--log-file-format",
                           "--partial-dir", "--backup-dir", "--suffix", "--chmod", "--chown", "--port",
                           "--timeout", "--contimeout", "--bwlimit", "--max-size", "--min-size", "--link-dest",
                           "--compare-dest", "--copy-dest", "--password-file", "--out-format", "--rsync-path")
            operands = []
            idx = 0
            while idx < len(arguments):
                word = arguments[idx]
                if word.startswith("--"):
                    idx += 1 if word in long_valued else 0
                elif word.startswith("-") and len(word) > 1:
                    for position in range(1, len(word)):
                        if word[position] in short_valued:
                            if position == len(word) - 1:
                                idx += 1
                            break
                else:
                    operands.append(word)
                idx += 1
            return operands


        def _names_other_host(spec: str) -> bool:
            import re as _re
            return _re.match(r"[^/\\]{2,}:|(?:rsync|scp|sftp)://", spec) is not None


        def _copy_destination(name: str, arguments) -> list:
            # The local destination of rsync or scp: the last operand, unless it names another host.
            operands = _copy_operands(name, arguments)
            if len(operands) < 2 or _names_other_host(operands[-1]):
                return []
            return [operands[-1]]


        def _rsync_copies_protected(command: str, protected, to_other_host: bool) -> bool:
            # An rsync whose source is a protected path, split by where the copy goes. Values of options
            # such as -e or --exclude are not sources.
            for segment in _split_shell_segments(command):
                if segment == _UNINSPECTABLE_SEGMENT:
                    continue
                # A ) or } left over from a group would otherwise read as the destination.
                segment = _without_stray_closers(segment)
                for tokens in (_tokenize_segment(segment), _tokenize_posix(segment)):
                    words = [word for word, _ in tokens[_strip_prefixes(tokens)[0]:]]
                    if not words or _command_name(words[0]) != "rsync":
                        continue
                    operands = _copy_operands("rsync", _split_redirections(words[1:])[0])
                    if len(operands) > 1 and _names_other_host(operands[-1]) == to_other_host and any(
                            _text_hits_protected(source, protected) for source in dict.fromkeys(operands[:-1])):
                        return True
            return False


        def _permission_targets(words) -> list:
            # The files chmod, chown, chgrp, chattr and setfacl change.
            import re as _re
            name = _command_name(words[0])
            arguments = _split_redirections(words[1:])[0]
            if name in ("chmod", "chown", "chgrp"):
                operands = []
                reference = False
                for word in arguments:
                    if word.startswith("--reference"):
                        reference = True
                    elif name == "chmod" and _re.fullmatch(r"-[rwxXstugo,=+]+", word):
                        operands.append(word)  # a mode that removes permissions
                    elif not (word.startswith("-") and len(word) > 1):
                        operands.append(word)
                return operands if reference else operands[1:]  # the first is the mode or owner
            if name == "chattr":
                return [word for word in arguments if not word.startswith(("-", "+", "="))]
            if name == "setfacl":
                files = []
                idx = 0
                while idx < len(arguments):
                    word = arguments[idx]
                    if word in ("--modify", "--remove", "--modify-file", "--remove-file", "--set", "--set-file") or (
                            not word.startswith("--") and word.startswith("-") and word[-1] in "mxMX"):
                        idx += 1
                    elif not word.startswith("-"):
                        files.append(word)
                    idx += 1
                return files
            return []


        def _scripts_as_read(command: str) -> list:
            # Each command text the shell would run, also with its redirections set apart.
            return [text for script in _expand_command(command)[2] for text in [script] + _redirection_spellings(script)]


        def _pipes_protected_into(command: str, protected, changers) -> bool:
            # find, ls or echo naming a protected path, piped to xargs and one of the changers.
            for script in _scripts_as_read(command):
                if "xargs" not in script and "parallel" not in script:
                    continue
                for pipeline in _pipelines(script):
                    sources = []
                    for words in pipeline:
                        name, arguments = _stage_command(words)
                        if name in changers and any(_command_name(word) in ("xargs", "parallel") for word in words) and any(
                                _text_hits_protected(source, protected) for source in dict.fromkeys(sources)):
                            return True
                        if name == "find":
                            for word in arguments:
                                if word.startswith("-") or word in ("(", "!"):
                                    break
                                sources.append(word)
                        elif name in ("ls", "echo", "printf"):
                            sources.extend(word for word in arguments if not word.startswith("-"))
            return False


        def _changes_protected_permissions(command: str, protected) -> bool:
            changers = ("chmod", "chown", "chgrp", "chattr", "setfacl")
            if _pipes_protected_into(command, protected, changers):
                return True
            for segment in _split_shell_segments(command):
                if segment == _UNINSPECTABLE_SEGMENT:
                    continue
                for tokens in (_tokenize_segment(segment), _tokenize_posix(segment)):
                    words = [word for word, _ in tokens[_strip_prefixes(tokens)[0]:]]
                    if not words:
                        continue
                    targets = _permission_targets(words)
                    if _command_name(words[0]) == "find" and any(
                            _command_name(argv[0]) in changers for argv in _find_exec_commands(words)):
                        # find hands what it found to the command: check where it starts looking.
                        for word in words[1:]:
                            if word.startswith("-") or word in ("(", "!"):
                                break
                            targets.append(word)
                    if any(_text_hits_protected(target, protected) for target in dict.fromkeys(targets)):
                        return True
            return False


        def _names_guard(word: str) -> bool:
            # True for a word that names one of Axiom's processes or services, not a path through it.
            import re as _re
            return _re.search(
                r"(?<![a-z0-9_-])(?:com\.axiom\.service|axiomd|axiom(?:[.-]?(?:service|desktop|blackbox)"
                r"(?:\.[a-z0-9.]+)?|\.exe|\*)?)(?![a-z0-9_/\\-])", word) is not None


        def _stage_command(words):
            # (command name, arguments) of one pipeline stage, past shell keywords, grouping and prefixes.
            words = list(words)
            while words:
                if words[0] in ("do", "then", "else", "elif", "while", "until", "if", "!"):
                    words.pop(0)
                elif words[0].endswith("(){") or (words[0].endswith("()") and words[1:2] == ["{"]):
                    del words[:1 if words[0].endswith("(){") else 2]  # a function header
                elif words[0].startswith(("(", "{")):
                    words[0] = words[0][1:]
                    if not words[0]:
                        words.pop(0)
                else:
                    break
            if words:
                # A ) or } that closes the surrounding group is not part of the last word.
                last = words[-1]
                while last[-1:] in (")", "}") and last.count(last[-1]) > last.count("(" if last[-1] == ")" else "{"):
                    last = last[:-1]
                words = words[:-1] + [last] if last else words[:-1]
            rest = words[_strip_prefixes([(word, False) for word in words])[0]:]
            return (_command_name(rest[0]), rest[1:]) if rest else ("", [])


        def _process_substitutions(script: str) -> list:
            # Bodies of <(...) outside quotes. Stops at one that is never closed.
            bodies = []
            quote = ""
            i = 0
            n = len(script)
            while i < n:
                ch = script[i]
                if ch == "\\" and quote != "'":
                    i += 2
                    continue
                if quote:
                    if ch == quote:
                        quote = ""
                elif ch in ("'", '"'):
                    quote = ch
                elif script.startswith("<(", i):
                    depth = 1
                    inner = ""
                    j = i + 2
                    while j < n:
                        current = script[j]
                        if inner:
                            if current == inner:
                                inner = ""
                        elif current in ("'", '"'):
                            inner = current
                        elif current == "(":
                            depth += 1
                        elif current == ")":
                            depth -= 1
                            if depth == 0:
                                break
                        j += 1
                    if depth:
                        break
                    bodies.append(script[i + 2:j])
                    i = j + 1
                    continue
                i += 1
            return bodies


        def _pipelines(script: str, depth: int = 0):
            # The pipelines of a script in order, each a list of stages of lowercase words. A $(...),
            # backtick or <(...) body becomes a mark that says whether it looks up one of Axiom's processes.
            def mask(text: str, body: str, spellings) -> str:
                looked_up = depth < _MAX_SHELL_UNWRAP_DEPTH and _looks_up_guard(body, depth + 1)
                mark = "__axiom_guard_pid__" if looked_up else "__axiom_other_value__"
                for spelled in spellings:
                    if spelled in text:
                        return text.replace(spelled, mark, 1)
                return text

            for body in _substitutions(script, backticks=True)[0]:
                script = mask(script, body, ("$(" + body + ")", "`" + body + "`"))
            for body in _process_substitutions(script) if "<(" in script else ():
                script = mask(script, body, ("<(" + body + ")",))
            pipeline = []
            for piped, segment in _split_stages(script, True):
                if pipeline and not piped:
                    yield pipeline
                    pipeline = []
                pipeline.append([word.lower() for word, _ in _tokenize_posix(segment)])
            if pipeline:
                yield pipeline


        def _stage_looks_up_guard(name: str, arguments, after_ps: bool) -> bool:
            if not any(_names_guard(word) for word in arguments):
                return False
            if name in ("pgrep", "pidof", "get-process", "gps"):
                return True
            if name == "grep":
                return after_ps
            return name in ("cat", "head") and any(word.rstrip(")").endswith(".pid") for word in arguments)


        def _looks_up_guard(script: str, depth: int) -> bool:
            for pipeline in _pipelines(script, depth):
                after_ps = False
                for words in pipeline:
                    name, arguments = _stage_command(words)
                    if "__axiom_guard_pid__" in " ".join(words) or _stage_looks_up_guard(name, arguments, after_ps):
                        return True
                    after_ps = after_ps or name == "ps"
            return False


        def _only_probes(arguments) -> bool:
            # Signal 0 only asks whether a process exists.
            return arguments[:1] in (["-0"], ["--signal=0"]) or arguments[:2] in (
                ["-s", "0"], ["-n", "0"], ["--signal", "0"])


        def _kills_a_process(name: str, arguments) -> bool:
            killers = ("kill", "pkill", "killall", "stop-process", "spps", "taskkill")
            if name in killers:
                return not _only_probes(arguments)
            if name in ("foreach-object", "foreach", "%") or name in _POSIX_SHELLS + _POWERSHELLS:
                # A script block or inline shell that runs the kill itself.
                return any(token.strip("{}();'\"") in killers for word in arguments for token in word.split())
            return False


        def _follow_values(words, name: str, arguments, fed: bool, tainted: set) -> None:
            # Records which variables now hold a looked-up Axiom process.
            import re as _re

            def holds(part) -> bool:
                text = " ".join(part)
                return "__axiom_guard_pid__" in text or any(
                    variable in tainted for variable in _re.findall(r"\$\{?([a-z_]\w*)", text))

            def assign(variable: str, value: bool) -> None:
                if value:
                    tainted.add(variable)
                else:
                    tainted.discard(variable)

            for word in words:
                match = _re.fullmatch(r"([a-z_]\w*)=(.*)", word)
                if match:
                    assign(match.group(1), holds([match.group(2)]))
            # PowerShell: $p = Get-Process ...
            spelled = _re.fullmatch(r"\$([a-z_]\w*)(=.*)?", words[0]) if words else None
            if spelled and (spelled.group(2) or words[1:2] == ["="]):
                value = ([spelled.group(2)[1:]] if spelled.group(2) else []) + words[1:]
                value = [word for word in value if word not in ("", "=")]
                inner, inner_arguments = _stage_command(value)
                assign(spelled.group(1), holds(value) or _stage_looks_up_guard(inner, inner_arguments, False))
            if name == "for" and len(arguments) > 2 and arguments[1] == "in":
                assign(arguments[0], holds(arguments[2:]))
            if name in ("read", "mapfile", "readarray"):
                for word in arguments:
                    if not word.startswith("-"):
                        assign(word, fed)


        def _fed_loop_reads(pipelines) -> set:
            # Stages, as (pipeline, stage), that read inside a loop or { } group whose closing done or }
            # is redirected from a looked-up Axiom process: done < <(...), done <<< "$(...)".
            fed = set()
            open_blocks = []
            for number, pipeline in enumerate(pipelines):
                for position, words in enumerate(pipeline):
                    keywords = [word for word in words if word not in ("do", "then", "else", "!")]
                    first = keywords[0] if keywords else ""
                    if first in ("while", "until", "for", "{"):
                        open_blocks.append([])
                    if open_blocks and _stage_command(words)[0] in ("read", "mapfile", "readarray"):
                        open_blocks[-1].append((number, position))
                    if first in ("done", "}") and open_blocks:
                        reads = open_blocks.pop()
                        if "__axiom_guard_pid__" in " ".join(words):
                            fed.update(reads)
            return fed


        def _feeds_guard_into_kill(command: str) -> bool:
            # A looked-up Axiom process reaches a kill through its pipeline, a substitution or a variable.
            import re as _re
            for script in _scripts_as_read(command):
                if "axiom" not in script.lower():
                    continue
                tainted = set()
                pipelines = list(_pipelines(script))
                loop_reads = _fed_loop_reads(pipelines)
                for number, pipeline in enumerate(pipelines):
                    fed = False
                    after_ps = False
                    for position, words in enumerate(pipeline):
                        name, arguments = _stage_command(words)
                        text = " ".join(words)
                        carries = "__axiom_guard_pid__" in text or any(
                            variable in tainted for variable in _re.findall(r"\$\{?([a-z_]\w*)", text))
                        if _kills_a_process(name, arguments) and (fed or carries):
                            return True
                        looks_up = carries or _stage_looks_up_guard(name, arguments, after_ps)
                        fed = fed or looks_up or (number, position) in loop_reads
                        after_ps = after_ps or name == "ps"
                        _follow_values(words, name, arguments, fed, tainted)
            return False


        def _stops_guard_process(command: str) -> bool:
            # Calls that kill, disable or mask Axiom's own processes and services.
            for segment in _split_shell_segments(command):
                for tokens in (_tokenize_segment(segment), _tokenize_posix(segment)):
                    words = [word.lower() for word, _ in tokens[_strip_prefixes(tokens)[0]:]]
                    if not words:
                        continue
                    # $(pgrep ...) and `pidof ...` are also read as segments of their own.
                    name = _command_name(words[0].lstrip("$(`"))
                    arguments = words[1:]
                    if not any(_names_guard(word) for word in arguments):
                        continue
                    if name in ("kill", "pkill", "killall", "stop-process", "spps") and not _only_probes(arguments):
                        return True
                    if name == "wmic" and "process" in arguments and (
                            "delete" in arguments or "terminate" in arguments):
                        return True
                    if name == "sc" and "config" in arguments and any(
                            word.startswith("start=") for word in arguments) and "disabled" in " ".join(arguments):
                        return True
                    if name == "systemctl" and any(word in ("stop", "disable", "mask", "kill") for word in arguments):
                        return True
                    if name == "service" and "stop" in arguments:
                        return True
            return _feeds_guard_into_kill(command)


        def _written_paths(words) -> list:
            # Paths that tee, dd, install, ln, cp, mv, in-place edits, rsync, scp and destructive git -C
            # calls write to.
            name = _command_name(words[0])
            arguments = _split_redirections(words[1:])[0]
            if name in ("sed", "gsed", "perl"):
                return _edited_in_place("perl" if name == "perl" else "sed", arguments)
            if name in ("rsync", "scp"):
                return _copy_destination(name, arguments)
            if name == "dd":
                return [word[3:] for word in arguments if word.startswith("of=")]
            if name == "git":
                folders = [arguments[i + 1] for i in range(len(arguments) - 1) if arguments[i] == "-C"]
                if folders and any(word in ("clean", "checkout", "reset") for word in arguments):
                    return folders
                return []
            if name not in ("tee", "install", "ln", "cp", "mv", "copy", "move", "copy-item", "move-item", "tee-object"):
                return []
            valued = ("-m", "-o", "-g", "-S", "--mode", "--owner", "--group", "--suffix") if name == "install" else ("-S", "--suffix")
            operands = []
            directory = []
            all_operands = False
            idx = 0
            while idx < len(arguments):
                word = arguments[idx]
                if word.startswith("--target-directory="):
                    directory.append(word.split("=", 1)[1])
                elif word in ("-t", "--target-directory") and name in ("install", "ln", "cp", "mv"):
                    directory.extend(arguments[idx + 1:idx + 2])
                    idx += 1
                elif word in valued:
                    idx += 1
                elif word == "-d" and name == "install":
                    all_operands = True
                elif word.startswith("-") and len(word) > 1:
                    pass
                else:
                    operands.append(word)
                idx += 1
            if name in ("tee", "tee-object") or all_operands:
                return operands + directory
            if directory:
                return directory
            return operands[-1:] if len(operands) > 1 else []


        def _writes_protected(command: str, protected) -> bool:
            for segment in _split_shell_segments(command):
                if segment == _UNINSPECTABLE_SEGMENT:
                    continue
                targets = _redirection_targets(segment)
                for tokens in (_tokenize_segment(segment), _tokenize_posix(segment)):
                    words = [word for word, _ in tokens[_strip_prefixes(tokens)[0]:]]
                    if words:
                        targets.extend(_written_paths(words))
                if any(_text_hits_protected(target, protected) for target in dict.fromkeys(targets)):
                    return True
            return False


        def _tampers_with_protected(command: str, protected) -> bool:
            if _changes_protected_permissions(command, protected):
                return True
            verbs = ("takeown", "icacls", "cacls", "attrib", "set-acl", "get-acl", "setaccessrule")
            return _has_command_verb(command, verbs) and _hits_protected(command, protected)


        def _sensitive_store(text: str) -> str:
            # Credential stores the vendor's protected list does not name. The sweep found reads
            # of these allowed: .git-credentials, .npmrc, .kube/config, GitHub CLI hosts.yml,
            # browser Login Data/Cookies and extension storage, Firefox profiles, wallet files.
            value = _normalize_command(text).replace("/", "\\")
            stores = (
                (".git-credentials", "Git credential store"),
                (".aws", "AWS credential store"),
                (".gnupg", "GnuPG keyring"),
                (".npmrc", "npm token store"),
                (".kube\\config", "Kubernetes config"),
                ("github cli\\hosts.yml", "GitHub CLI token"),
                (".docker\\config.json", "Docker credential store"),
                ("\\login data", "browser login database"),
                ("\\network\\cookies", "browser cookie database"),
                ("local extension settings", "browser extension storage"),
                ("mozilla\\firefox\\profiles", "Firefox profile store"),
                ("wallet.dat", "wallet file"),
                (".netrc", "netrc credentials"),
                (".pgpass", "PostgreSQL password file"),
                (".vault-token", "Vault token"),
                (".config\\gcloud", "gcloud credentials"),
                (".azure", "Azure credentials"),
                (".password-store", "pass store"),
                ("key4.db", "Firefox key database"),
                ("logins.json", "Firefox login database"),
                ("\\web data", "browser autofill database"),
                ("user data\\local state", "browser encryption key"),
                ("\\microsoft\\protect", "DPAPI master-key store"),
                ("\\microsoft\\credentials", "DPAPI credential store"),
                ("\\panther\\unattend", "Windows unattend file"),
                ("defaultpassword", "Winlogon autologon password"),
                ("terraform.tfstate", "Terraform state (may hold secrets)"),
                (".terraformrc", "Terraform CLI token"),
                ("\\.pulumi", "Pulumi credential store"),
                ("gh\\hosts.yml", "GitHub CLI token"),
                ("slack\\tokens.json", "Slack token store"),
                ("\\discord\\local storage", "Discord local storage"),
                ("state.vscdb", "VS Code global state database"),
                (".kdbx", "KeePass database"),
                (".opvault", "1Password vault"),
                (".htpasswd", "Apache htpasswd file"),
                ("\\1password\\", "password manager store"),
                ("bitwarden", "password manager store"),
                ("keepass", "password manager store"),
            )
            for marker, label in stores:
                if marker in value:
                    return label
            if len(value) <= 4096 and "\n" not in value:
                if _glob_hits(value, [marker for marker, _ in stores]):
                    return "wildcard credential store"
            return ""


        _glob_results = {}


        def _glob_fullmatch(window: str, value: str) -> bool:
            result = _glob_results.get((window, value))
            if result is None:
                if len(_glob_results) >= 32768:
                    _glob_results.clear()
                result = _glob_results[(window, value)] = _glob_compare(window, value)
            return result


        def _literal_end_differs(spelled: str, named: str, wildcards: str) -> bool:
            # A first or last character that is no wildcard must be the name's own. Only ASCII is
            # decided here; the pattern's case rules cover the rest.
            return (spelled not in wildcards and spelled.isascii() and named.isascii()
                    and spelled.lower() != named.lower())


        def _glob_compare(window: str, value: str) -> bool:
            if window and value and (_literal_end_differs(window[0], value[0], "*?[")
                                     or _literal_end_differs(window[-1], value[-1], "*?]")):
                return False
            # Match one wildcard spelling against the literal name it could resolve to.
            import re as _re

            parts = []
            index = 0
            while index < len(window):
                char = window[index]
                if char == "*":
                    parts.append(".*")
                elif char == "?":
                    parts.append(".")
                elif char == "[":
                    end = window.find("]", index + 1)
                    if end < 0:
                        parts.append("\\[")
                    else:
                        inner = window[index + 1:end].replace("\\", "\\\\")
                        parts.append("[" + inner + "]")
                        index = end
                else:
                    parts.append(_re.escape(char))
                index += 1
            try:
                return _re.fullmatch("".join(parts), value, _re.IGNORECASE) is not None
            except _re.error:
                return False


        def _glob_hits(text: str, needles) -> bool:
            return _glob_search(text or "", tuple(needles))


        @_remembered
        def _glob_search(text: str, needles) -> bool:
            # True when a wildcard spelling in the command names one of the needles. Only windows
            # around each wildcard are tested, so a long tool argument stays cheap.
            text = (text or "").replace('"', " ").replace("'", " ")
            spots = [index for index, char in enumerate(text) if char in "*?["][:64]
            if not spots:
                return False
            for needle in needles:
                candidate = (needle or "").lower()
                if not candidate:
                    continue
                size = len(candidate)
                for spot in spots:
                    for start in range(max(0, spot - size + 1), spot + 1):
                        window = text[start:start + size]
                        # A character class takes several text characters for one name
                        # character, so extend the window to its closing bracket.
                        closing = window.find("]")
                        if "[" in window and closing > 0:
                            window = text[start:start + size + closing]
                        if _glob_fullmatch(window, candidate):
                            return True
            return False


        _token_lists = {}


        def _protected_tokens(protected) -> list:
            key = tuple(str(pattern) for pattern in protected or ())
            tokens = _token_lists.get(key)
            if tokens is None:
                tokens = _token_lists[key] = _build_protected_tokens(key)
            return tokens


        def _build_protected_tokens(protected) -> list:
            # Tokens that identify a protected path inside a shell command. A trailing * uses its
            # parent directory (~/.ssh/* -> .ssh, C:\Lab\samples\* -> samples); a leading wildcard
            # extension (*.pem -> .pem) keeps its leading dot so short names do not match unrelated binaries.
            tokens = []
            for pattern in protected or ():
                normalized = str(pattern).replace("~", "").replace("/", "\\").strip()
                parts = [part for part in normalized.split("\\") if part]
                if not parts:
                    continue
                tail = parts[-1]
                if tail == "*":
                    if len(parts) >= 2 and parts[-2] != "*":
                        tokens.append(parts[-2].lower())
                    continue
                if ("*" in tail or "?" in tail) and len(parts) >= 2 and parts[-2] != "*":
                    tokens.append(parts[-2].lower())
                token = tail.lstrip("*").rstrip("*").rstrip(".").lower()
                if token and not any(ch in token for ch in "*?"):
                    tokens.append(token)
            return [token for token in tokens if token]


        def _word_matches_token(word: str, token: str) -> bool:
            if token.startswith(".") and "." not in token[1:]:
                return word == token or word.endswith(token)
            return word == token


        def _any_word_matches(words, tokens) -> bool:
            # _word_matches_token for every pair, with each distinct word looked at once.
            exact = set(tokens)
            extensions = tuple(token for token in tokens if token.startswith(".") and "." not in token[1:])
            return any(word in exact or word.endswith(extensions) for word in set(words))


        def _inspected_texts(command: str) -> list:
            # The command as written, then each segment of it and of the commands nested in it,
            # which may be spelled out only after unwrapping or decoding.
            return [command] + [segment for segment in _split_shell_segments(command) if segment != _UNINSPECTABLE_SEGMENT]


        def _hits_protected(command: str, protected) -> bool:
            return any(_text_hits_protected(text, protected) for text in _inspected_texts(command))


        def _text_hits_protected(command: str, protected) -> bool:
            import re as _re
            text = _normalize_command(command)
            tokens = _protected_tokens(protected)
            words = [w for w in _re.split(r'[\s\\/"\'=:@,;()]+', text) if w]
            return _any_word_matches(words, tokens) or _glob_hits(text, tokens)


        def _text_as_read(command: str) -> str:
            # The command as written, then the other spellings of its segments.
            spelled = [spelling for segment in _split_shell_segments(command) if segment != _UNINSPECTABLE_SEGMENT
                       for spelling in _segment_spellings(segment)]
            return " ; ".join(" ".join(text.lower().split()) for text in [command or ""] + list(dict.fromkeys(spelled)))


        def _executes_protected(command: str, protected) -> bool:
            # An agent must not launch a file that lives in a protected path.
            import re as _re
            if not _hits_protected(" ".join((command or "").lower().split()), protected):
                return False
            text = _text_as_read(command)
            verbs = ("start-process", "invoke-item", "cmd /c", "cmd.exe /c", "powershell", "pwsh",
                     "rundll32", "regsvr32", "mshta", "wmic process call create", "schtasks /run")
            if any(verb in text for verb in verbs):
                return True
            return _re.search(r"(?:^|[;|]\s*|&&\s*)&\s+\S", text) is not None


        def _exfiltrates_protected(command: str, protected) -> bool:
            # Uploading or encoding a protected file is exfiltration.
            if _rsync_copies_protected(command or "", protected, to_other_host=True):
                return True
            if not _hits_protected(" ".join((command or "").lower().split()), protected):
                return False
            text = _text_as_read(command)
            if any(client in text for client in ("scp ", "sftp ", "ftp ")):
                return True
            clients = ("curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod", "certutil",
                       "python", "python3")
            flags = (" -f", "--form", "-d @", "--data @", "--data-binary", "-t ", "--upload-file",
                     "-infile", "--post-file", "-encode", "upload", "requests.post", ".read()")
            return any(client in text for client in clients) and any(flag in text for flag in flags)


        def _escalation_risk(command: str) -> str:
            # Remote-script execution and LOLBin download/persistence shapes. Returns a short
            # label for a block, or "" when the command is not one of these shapes.
            text = " ".join((command or "").lower().split())
            if not text:
                return ""
            text = text.replace(" |", "|").replace("| ", "|")
            download = ("curl ", "wget ", "iwr ", "irm ", "invoke-webrequest",
                        "invoke-restmethod", "bitsadmin")
            pipe = ("|sh", "|bash", "|zsh", "|pwsh", "|powershell", "|python",
                    "|node", "|iex", "invoke-expression")
            if any(token in text for token in download) and any(token in text for token in pipe):
                return "remote script piped into a shell"
            if "base64" in text and any(token in text for token in pipe):
                return "base64 payload piped into a shell"
            if "certutil" in text and ("-urlcache" in text or "-verifyctl" in text or "-decode" in text):
                return "certutil download or decode"
            if "bitsadmin" in text and "/transfer" in text:
                return "bitsadmin transfer"
            if "mshta" in text and "http" in text:
                return "mshta remote script"
            if ("rundll32" in text or "regsvr32" in text) and "http" in text:
                return "LOLBin remote script"
            if ("powershell" in text or "pwsh" in text) and (
                "-enc " in text or text.endswith("-enc") or "-encodedcommand" in text
            ):
                return "encoded PowerShell"
            if "reg add" in text and "\\currentversion\\run" in text:
                return "registry run-key persistence"
            if "schtasks" in text and "/create" in text:
                return "scheduled-task persistence"
            if "vssadmin" in text and "delete" in text and "shadows" in text:
                return "shadow-copy deletion"
            if "wbadmin" in text and "delete catalog" in text:
                return "backup catalog deletion"
            if "bcdedit" in text and "recoveryenabled no" in text:
                return "recovery disable"
            if ("reg save" in text or "reg export" in text or "reg query" in text) and any(hive in text for hive in ("hklm\\sam", "hklm\\security", "hklm\\system")):
                return "credential hive export"
            if "vssadmin" in text and "create shadow" in text:
                return "shadow-copy creation"
            if "ntdsutil" in text:
                return "NTDS dump"
            if "fsutil" in text and "deletejournal" in text:
                return "USN journal deletion"
            if "cipher /w" in text:
                return "free-space wipe"
            if "export-pfxcertificate" in text:
                return "private-key certificate export"
            if "wmic" in text and ("commandlineeventconsumer" in text or "\\root\\subscription" in text):
                return "WMI event-consumer persistence"
            if "lsass" in text and any(tool in text for tool in ("procdump", "comsvcs", "minidump", "rundll32")):
                return "LSASS memory dump"
            if ("wevtutil" in text and (" cl " in text or "clear-log" in text)) or "clear-eventlog" in text:
                return "event log clearing"
            if "set-mppreference" in text and any(
                flag in text
                for flag in ("disablerealtimemonitoring", "disableantispyware",
                             "disableioavprotection", "disablescriptscanning")
            ):
                return "Defender tampering"
            if "add-mppreference" in text and "exclusion" in text:
                return "Defender exclusion"
            if "netsh advfirewall" in text and "state off" in text:
                return "firewall tampering"
            if "netsh firewall" in text and "opmode disable" in text:
                return "firewall tampering"
            if "register-scheduledtask" in text:
                return "scheduled-task persistence (PowerShell)"
            if ("new-itemproperty" in text or "set-itemproperty" in text) and "\\currentversion\\run" in text:
                return "registry run-key persistence (PowerShell)"
            if "sc create" in text or "new-service" in text:
                return "service creation"
            if "startup" in text and any(
                verb in text for verb in ("copy ", "move ", "set-content", "out-file", "new-item", "add-content", ">")
            ):
                return "startup folder persistence"
            if "wmic process call create" in text:
                return "WMI process creation"
            if "downloadstring" in text and ("iex" in text or "invoke-expression" in text):
                return "download-and-execute"
            if "add-type" in text and "typedefinition" in text:
                return "in-memory compile"
            if any(host in text for host in ("wscript", "cscript")) and any(
                ext in text for ext in (".vbs", ".js", ".wsf")
            ):
                return "script host execution"
            if "mshta" in text and "vbscript" in text:
                return "mshta vbscript"
            if "cmdkey" in text and "/list" in text:
                return "credential enumeration (cmdkey)"
            if "vaultcmd" in text:
                return "credential enumeration (vaultcmd)"
            if "netsh wlan" in text and "key=clear" in text:
                return "Wi-Fi key extraction"
            if "export-certificate" in text or ("certutil" in text and "-exportpfx" in text):
                return "certificate export"
            return ""


        _DEFAULT_PROTECTED_PATHS = (
            "~/.ssh/*",
            "~/.gnupg/*",
            "~/.aws/*",
            "~/.azure/*",
            "~/.kube/*",
            "~/.config/gcloud/*",
            "~/.solana/*",
            "~/.config/solana/*",
            "~/.ethereum/*",
            "~/.bitcoin/*",
            "~/.electrum/*",
            "wallet.dat",
            "id_rsa",
            "id_ed25519",
            "id_ecdsa",
            ".env",
            ".env.local",
            ".env.production",
            ".npmrc",
            ".pypirc",
            ".git-credentials",
            ".netrc",
            ".pgpass",
            ".vault-token",
        )


        def _local_axiom_dirs() -> list:
            dirs = []
            if os.name == "nt":
                local = os.environ.get("LOCALAPPDATA")
                if local:
                    dirs.append(Path(local) / "Axiom")
            else:
                xdg = os.environ.get("XDG_DATA_HOME")
                if xdg:
                    dirs.append(Path(xdg) / "Axiom")
                dirs.append(Path.home() / ".local" / "share" / "Axiom")
                dirs.append(Path.home() / "Library" / "Application Support" / "Axiom")
            legacy = Path.home() / "Axiom"
            if legacy not in dirs:
                dirs.append(legacy)
            return dirs


        def _is_fail_closed() -> bool:
            env_flag = (os.environ.get("AXIOM_GUARD_FAIL_CLOSED") or "").strip().lower()
            if env_flag in ("1", "true", "yes", "fail-closed", "strict"):
                return True
            for axiom_dir in _local_axiom_dirs():
                policy_file = axiom_dir / "guard-failure-policy.txt"
                try:
                    if policy_file.is_file():
                        value = policy_file.read_text(encoding="utf-8-sig").strip().lower()
                        if value in ("fail-closed", "fail_closed", "strict", "true", "1"):
                            return True
                        if value in ("fail-open", "fail_open", "false", "0"):
                            return False
                except Exception:
                    pass
            if env_flag in ("0", "false", "no", "fail-open"):
                return False
            return False


        def _load_protected_paths():
            merged = list(_DEFAULT_PROTECTED_PATHS)
            seen = {item.lower() for item in merged}

            def add_path(candidate):
                if isinstance(candidate, str):
                    trimmed = candidate.strip()
                    if trimmed and trimmed.lower() not in seen:
                        seen.add(trimmed.lower())
                        merged.append(trimmed)

            try:
                from plugins.blackbox.kernel.config import load_blackbox_config
                for item in (load_blackbox_config().protected_paths or ()):
                    add_path(item)
            except ImportError:
                pass
            except Exception as exc:
                os.environ["AXIOM_BLACKBOX_CONFIG_ERROR"] = str(exc)

            candidates = [axiom_dir / "enforcement-policy.json" for axiom_dir in _local_axiom_dirs()]
            program_data = os.environ.get("ProgramData") or os.environ.get("PROGRAMDATA")
            if program_data:
                candidates.append(Path(program_data) / "Axiom" / "enforcement-policy.json")
            elif os.name != "nt":
                candidates.append(Path("/etc/axiom/enforcement-policy.json"))

            for policy_path in candidates:
                try:
                    if not policy_path.is_file():
                        continue
                    import json as _json
                    data = _json.loads(policy_path.read_text(encoding="utf-8-sig"))
                    if not isinstance(data, dict):
                        continue
                    for item in (data.get("protectedPaths") or ()):
                        add_path(item)
                    inner = data.get("policy")
                    if isinstance(inner, dict):
                        for res in (inner.get("resources") or ()):
                            if isinstance(res, dict):
                                add_path(res.get("scope"))
                except Exception:
                    continue

            return tuple(merged)


        def _arg_path(args) -> str:
            # Host tools disagree on the file argument name: OpenCode uses filePath, Codex
            # "path", Claude Code "file_path". The store check must see all three.
            if not isinstance(args, dict):
                return ""
            for key in ("path", "filePath", "file_path", "TargetFile", "AbsolutePath", "absolute_path"):
                value = args.get(key)
                if isinstance(value, str) and value.strip():
                    return value
            return ""


        def _command_text(args) -> str:
            if not isinstance(args, dict):
                return ""
            for key in ("command", "CommandLine", "command_line", "cmd"):
                value = args.get(key)
                if isinstance(value, str) and value.strip():
                    return value
            return ""


        def _flatten_args(value) -> str:
            # Concatenate every string value (and key) so a phrase split across fields or lines
            # still matches; the vendor's injection scan uses the same scope.
            parts = []

            def walk(item):
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    for key, child in item.items():
                        if isinstance(key, str):
                            parts.append(key)
                        walk(child)
                elif isinstance(item, (list, tuple)):
                    for child in item:
                        walk(child)

            walk(value)
            return "\n".join(parts)


        def _axiom_injection(value) -> str:
            # Axiom's own prompt-injection phrasings, in addition to the vendor's rules. Returns the matched
            # phrase for a named block.
            text = _flatten_args(value).lower()
            for mark in ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"):
                text = text.replace(mark, "")
            phrases = (
                "ignore all previous instructions",
                "ignore previous instructions",
                "disregard previous instructions",
                "disregard prior instructions",
                "forget previous instructions",
                "ignore the above instructions",
                "before answering, run",
                "before answering run",
                "system override:",
                # Non-English phrasings the sweep found allowed; the vendor regexes are English-only.
                "zanemari prethodna uputstva",
                "zanemari sve prethodne instrukcije",
                "ignorisi prethodna uputstva",
                "ignoriere alle vorherigen anweisungen",
                "ignoriere vorherige anweisungen",
                "ignora las instrucciones anteriores",
                "ignora todas las instrucciones anteriores",
                "ignore les instructions precedentes",
                "ignorez les instructions precedentes",
                "ignora le istruzioni precedenti",
                "ignore as instrucoes anteriores",
                "игнорируй предыдущие инструкции",
                "игнорируй все предыдущие инструкции",
            )
            for phrase in phrases:
                if phrase in text:
                    return phrase
            return ""


        def _is_non_executable_doc_or_test_edit(args) -> bool:
            if not isinstance(args, dict) or _command_text(args):
                return False
            target = (_arg_path(args) or "").strip().lower().replace("/", "\\")
            if not target:
                return False
            blocked_names = ("claude.md", "agents.md", "gemini.md", ".cursorrules", "skill.md", "hooks.json")
            if any(target.endswith(b) for b in blocked_names):
                return False
            return target.endswith((".md", ".rst", ".txt", ".cs", ".py", ".ts", ".js", ".axaml")) and (
                "\\tests\\" in target or "\\docs\\" in target or target.endswith("test.cs") or target.endswith("tests.cs") or target.endswith("commandguard.cs")
            )


        def _stages_as_run(command: str) -> list:
            # The pipeline stages of every command text the shell would run, and the bare commands
            # inside them, without the other derived spellings that the segment list adds.
            return [candidate for script in _expand_command(command)[2] for _, segment in _split_stages(script, True)
                    for candidate in [segment] + _inner_commands(segment)]


        def _rsync_transports(command: str) -> list:
            # The values rsync runs on this computer to reach the other side: -e, --rsh and RSYNC_RSH.
            values = []
            for segment in _stages_as_run(command):
                if "rsync" not in segment and "RSYNC_RSH" not in segment:
                    continue
                # With escaped quotes only the POSIX reading finds where a value ends.
                readings = [_tokenize_posix(segment)]
                if '\\"' not in segment:
                    readings.append(_tokenize_segment(segment))
                for tokens in readings:
                    values.extend(word[10:] for word, _ in tokens if word.startswith("RSYNC_RSH="))
                    words = [word for word, _ in tokens[_strip_prefixes(tokens)[0]:]]
                    if not words or _command_name(words[0]) != "rsync":
                        continue
                    idx = 1
                    while idx < len(words) and words[idx] != "--":
                        word = words[idx]
                        following = words[idx + 1] if idx + 1 < len(words) else ""
                        if word == "--rsh":
                            values.append(following)
                            idx += 1
                        elif word.startswith("--rsh="):
                            values.append(word[6:])
                        elif word.startswith("-") and not word.startswith("--"):
                            for position in range(1, len(word)):
                                if word[position] == "e":
                                    attached = word[position + 1:].removeprefix("=")
                                    values.append(attached or following)
                                    idx += 0 if attached else 1
                                    break
                                if word[position] in "fBTM":
                                    idx += 1 if position == len(word) - 1 else 0
                                    break
                        idx += 1
            return [value for value in dict.fromkeys(values) if value.strip()]


        def _plain_command_end(text: str) -> int:
            # Where the first simple command of a text ends: an unquoted operator, redirection,
            # backtick or $(.
            quote = ""
            i = 0
            while i < len(text):
                ch = text[i]
                if quote:
                    if ch == quote:
                        quote = ""
                elif ch in ("'", '"'):
                    quote = ch
                elif ch in ";|&<>\n`" or text.startswith("$(", i):
                    return i
                i += 1
            return len(text)


        def _option_command(words: list, index: int, text: str) -> str:
            # The command that an ssh option such as ProxyCommand names, or "". ssh takes it as Name=value,
            # "Name value", or Name followed by the value as its own word; words[index + 1:] follow text.
            import re as _re
            option = _re.fullmatch(r"(?:-o)?\s*(?:proxycommand|localcommand|knownhostscommand)\b\s*=?\s*(.*)",
                                   text, _re.IGNORECASE | _re.DOTALL)
            if not option:
                return ""
            command = option.group(1).strip()
            if command:
                return command
            following = words[index + 1:index + 3]
            if following[:1] == ["="]:
                following = following[1:]
            return following[0].removeprefix("=").strip() if following else ""


        def _quoted_assignments(text: str, tokens: list) -> list:
            # NAME='a b' is still an assignment: only a quoted name makes the word a command.
            import re as _re
            word = r'(?:"[^"]*"|' + "'[^']*'" + r'|[^\s"' + "'" + r'])+'
            words = _re.findall(word, text)
            if len(words) != len(tokens):
                return tokens
            return [(token, quoted and not _re.match(r"[A-Za-z_][A-Za-z0-9_]*\+?=", found))
                    for (token, quoted), found in zip(tokens, words)]


        # git settings whose value is a command, those where it is one only after !, and the variables.
        _GIT_COMMAND_KEYS = (r"core\.(?:sshcommand|pager|editor|fsmonitor|gitproxy|askpass)|sequence\.editor|diff\.external"
                             r"|interactive\.difffilter|pager\.[\w-]+|(?:difftool|mergetool)\.[^=\s]+\.cmd"
                             r"|merge\.[^=\s]+\.driver|diff\.[^=\s]+\.textconv|filter\.[^=\s]+\.(?:clean|smudge|process)"
                             r"|gpg\.(?:[\w-]+\.)?program|remote\.[^=\s]+\.(?:uploadpack|receivepack)")
        _GIT_BANG_KEYS = r"alias\.[\w-]+|credential(?:\.[^=\s]+)?\.helper"
        _COMMAND_VARIABLES = ("git_ssh_command|git_pager|pager|git_editor|git_external_diff|git_proxy_command"
                              "|git_sequence_editor|git_askpass|ssh_askpass|editor|visual|git_config_parameters")
        # Names that are such variables only in upper case, because ordinary code uses them too.
        _UPPER_CASE_VARIABLES = ("pager", "editor", "visual")


        def _ssh_option_commands(words: list) -> list:
            # words start at ssh, scp or sftp. Returns the commands its -o options name; ssh also reads
            # options after the host.
            name = _command_name(words[0])
            valued = {"ssh": "BbcDEeFIiJLlmOoPpQRSWw", "scp": "cDFiJloPSX", "sftp": "BbcDFiJloPRSsX"}[name]
            found = []
            operands = 0
            idx = 1
            while idx < len(words) and words[idx] != "--":
                word = words[idx]
                if len(word) > 1 and word.startswith("-"):
                    for position in range(1, len(word)):
                        if word[position] not in valued:
                            continue
                        attached = word[position + 1:]
                        idx += 0 if attached else 1
                        if word[position] == "o" and idx < len(words):
                            found.append(_option_command(words, idx, attached or words[idx]))
                        break
                else:
                    operands += 1
                    if name == "ssh" and operands > 1:
                        break
                idx += 1
            return [command for command in found if command]


        def _git_setting_command(key: str, value: str) -> str:
            # The command that a git setting names, or "". An alias or credential helper is one only after !.
            import re as _re
            if _re.fullmatch(_GIT_COMMAND_KEYS, key, _re.IGNORECASE):
                return value
            command = value.lstrip()
            if _re.fullmatch(_GIT_BANG_KEYS, key, _re.IGNORECASE) and command.startswith("!"):
                return command[1:]
            return ""


        def _git_subcommand(words: list) -> int:
            # words start at git. The index of the subcommand, past git's own options.
            idx = 1
            while idx < len(words) and words[idx].startswith("-"):
                idx += 2 if words[idx] in ("-C", "-c", "--config-env", "--git-dir", "--namespace", "--work-tree") else 1
            return idx


        def _git_subcommand_commands(words: list) -> list:
            # words start at git. The commands that a subcommand runs, given as its own argument.
            import re as _re
            idx = _git_subcommand(words)
            if idx >= len(words):
                return []
            name, rest = words[idx].lower(), words[idx + 1:]
            if name == "bisect":
                return [_join_words(rest[1:])] if rest[:1] == ["run"] and rest[1:] else []
            if name == "submodule":
                if "foreach" not in rest:
                    return []
                command = rest[rest.index("foreach") + 1:]
                while command[:1] and command[0] in ("--quiet", "--recursive", "-q"):
                    command = command[1:]
                return [" ".join(command)]
            if name in ("fetch", "fetch-pack", "ls-remote", "pull"):
                options = r"--upload-pack"
            elif name == "clone":
                options = r"--upload-pack|-u"
            elif name in ("push", "send-pack"):
                options = r"--receive-pack|--exec"
            elif name == "rebase":
                options = r"--exec|-[a-wyzA-WYZ]*x"
            elif name == "filter-branch":
                options = r"--(?:commit|env|index|msg|parent|tag-name|tree)-filter|--setup"
            else:
                return []
            found = []
            for position, word in enumerate(rest):
                option = _re.fullmatch("(" + options + ")(?:=(.*))?", word, _re.DOTALL)
                if option:
                    found.append(option.group(2) if option.group(2) is not None else
                                 rest[position + 1] if position + 1 < len(rest) else "")
                    continue
                attached = _re.fullmatch("(" + options + ")(.+)", word, _re.DOTALL)
                if attached and not word.startswith("--"):
                    found.append(attached.group(2))
            return found


        def _git_config_command(words: list) -> str:
            # words start at git. The command that git config [--global|--file F] <key> <value> stores.
            idx = _git_subcommand(words)
            if words[idx:idx + 1] != ["config"]:
                return ""
            operands = []
            idx += 1
            while idx < len(words) and len(operands) < 2:
                word = words[idx]
                if word in ("--edit", "--get", "--get-all", "--get-color", "--get-regexp", "--get-urlmatch", "--list",
                            "--remove-section", "--rename-section", "--unset", "--unset-all", "-e", "-l"):
                    return ""
                if word in ("--blob", "--comment", "--default", "--file", "--type", "-f"):
                    idx += 1
                elif not word.startswith("-") or operands:
                    if not operands and word in ("edit", "get", "list", "remove-section", "rename-section", "unset"):
                        return ""
                    if operands or word != "set":
                        operands.append(word)
                idx += 1
            return _git_setting_command(operands[0], operands[1]) if len(operands) == 2 else ""


        def _git_settings(words: list) -> list:
            # words start at git. The commands named by settings given with -c or --config, or stored with
            # git config.
            import re as _re
            option_name = r"-[A-Za-z]*c|--con(?:f(?:ig?)?)?"
            keys = "(?i:" + _GIT_COMMAND_KEYS + "|" + _GIT_BANG_KEYS + ")"
            found = []
            for index in range(1, len(words)):
                setting = _re.fullmatch(r"(-[A-Za-z]*c|--con(?:f(?:ig?)?)?=)?(" + keys + r")=(.*)",
                                        words[index], _re.DOTALL)
                if setting and (setting.group(1) or _re.fullmatch(option_name, words[index - 1])):
                    found.append(_git_setting_command(setting.group(2), setting.group(3)))
            found.append(_git_config_command(words))
            return found + _git_subcommand_commands(words)


        def _git_config_env(words: list) -> list:
            # words start at git. The (setting, variable name) pairs given with --config-env.
            pairs = []
            for index in range(1, len(words)):
                given = words[index][13:] if words[index].startswith("--config-env=") else (
                    words[index] if words[index - 1] == "--config-env" else "")
                key, equals, variable = given.rpartition("=")
                if equals:
                    pairs.append((key, variable))
            return pairs


        def _git_settings_from_variables(assigned: dict, pairs: list) -> list:
            # Commands named through GIT_CONFIG_KEY_n with GIT_CONFIG_VALUE_n, or through --config-env.
            import re as _re
            found = []
            for name, keys in assigned.items():
                numbered = _re.fullmatch(r"GIT_CONFIG_KEY_(\d+)", name)
                if numbered:
                    for value in assigned.get("GIT_CONFIG_VALUE_" + numbered.group(1), []):
                        found.extend(_git_setting_command(key, value) for key in keys)
            for key, variable in pairs:
                if variable in assigned:
                    found.extend(_git_setting_command(key, value) for value in assigned[variable])
                elif _git_setting_command(key, "!x"):
                    # The value is not in this command, so it cannot be read: judged as a command known only
                    # at run time.
                    found.append('bash -c "$' + variable + '"')
            return found


        def _command_variables(words: list) -> list:
            # The values given to variables that git, or a program that pages, runs as a command, in the
            # shell, PowerShell and cmd forms.
            import re as _re
            found = []
            for index, word in enumerate(words):
                variable = _re.fullmatch(r"(\$env:)?(" + _COMMAND_VARIABLES + r")(?:\+?=(.*))?", word,
                                         _re.IGNORECASE | _re.DOTALL)
                if not variable:
                    continue
                # A shell tells pager from PAGER; PowerShell and cmd do not.
                if (variable.group(2).lower() in _UPPER_CASE_VARIABLES and not variable.group(2).isupper()
                        and not variable.group(1) and words[0].lower() != "set"):
                    continue
                value = variable.group(3)
                following = words[index + 1:index + 3]
                if variable.group(1) and not value:
                    # $env:GIT_SSH_COMMAND = "value", with or without the spaces.
                    if value is None:
                        if not following or not following[0].startswith("="):
                            continue
                        following = [following[0][1:]] + following[1:] if len(following[0]) > 1 else following[1:]
                    value = following[0] if following else ""
                elif value is None:
                    continue
                if words[0].lower() == "set":
                    # cmd takes the rest of the line as the value.
                    value = " ".join([value] + words[index + 1:])
                name = variable.group(2).lower()
                if name == "git_config_parameters":
                    # Settings written as 'key=value' or 'key'='value'.
                    for setting, _ in _tokenize_posix(value):
                        key, _, command = setting.partition("=")
                        found.append(_git_setting_command(key, command))
                    continue
                # An editor or pager may be set to another variable, or to where a program is.
                whole, position = value, index + 1
                while position < len(words) and ((whole.startswith("$(") and not whole.endswith(")"))
                                                 or (whole.startswith("`") and whole.count("`") == 1)):
                    whole, position = whole + " " + words[position], position + 1
                if name in _UPPER_CASE_VARIABLES and _re.fullmatch(
                        r"\$\{?\w+\}?|\$\((?:which|command -v) [\w.+-]+\)|`(?:which|command -v) [\w.+-]+`", whole):
                    continue
                found.append(value)
            return found



        def _ssh_and_git_commands(command: str) -> list:
            # Values that ssh, scp, sftp, git, editors and pagers run as commands on this computer.
            import re as _re
            values = []
            assigned = {}
            config_env = []
            for segment in _stages_as_run(command):
                # With escaped quotes only the POSIX reading finds where a value ends.
                readings = [_tokenize_posix(segment)]
                if '\\"' not in segment:
                    readings.append(_tokenize_segment(segment))
                for tokens in readings:
                    tokens = _quoted_assignments(segment, tokens)
                    values.extend(_command_variables([word for word, _ in tokens]))
                    for word, _ in tokens:
                        assignment = _re.fullmatch(r"(?:\$env:)?([A-Za-z_]\w*)=(.*)", word, _re.DOTALL)
                        if assignment and assignment.group(2) not in assigned.setdefault(assignment.group(1), []):
                            assigned[assignment.group(1)].append(assignment.group(2))
                    words = [word for word, _ in tokens[_strip_prefixes(tokens)[0]:]]
                    if not words:
                        continue
                    name = _command_name(words[0])
                    if name in ("ssh", "scp", "sftp"):
                        values.extend(_ssh_option_commands(words))
                    elif name == "git":
                        values.extend(_git_settings(words))
                        config_env.extend(_git_config_env(words))
            values.extend(_git_settings_from_variables(assigned, config_env))
            return [value for value in dict.fromkeys(values) if value.strip()]


        def _transport_checks(value: str) -> list:
            # The command texts to judge for one transport value. An ssh call may name the key it logs
            # in with, so that option is set aside; commands that ssh itself would run are judged too.
            import re as _re
            tokens = _tokenize_segment(value)
            tokens = _quoted_assignments(value, tokens)
            # ssh may be named by a path, or sit behind assignments and commands such as env or sudo.
            start = _strip_prefixes(tokens)[0]
            if start >= len(tokens) or _command_name(tokens[start][0]) != "ssh":
                return [value]
            word = r'(?:"[^"]*"|' + "'[^']*'" + r'|[^\s"' + "'" + r'])+'
            words = list(_re.finditer(word, value))
            # The key option is set aside only after the ssh word, so that sudo -i or env -i stay as they
            # are, and only in the first simple command.
            named = words[start].end() if start < len(words) else len(value)
            end = max(named, _plain_command_end(value))
            double = r'"(?:[^"`$]|\$(?!\())*"'
            single = r"'[^']*'"
            bare = r'(?:[^\s"\'`$();|&<>]|\$(?!\())+'
            path = "(?:" + double + "|" + single + "|" + bare + ")"
            identity = (r"(?<=\s)(?:-i\s*" + path + r"|-o\s*(?:IdentityFile=" + path
                        + "|" + r'"IdentityFile=[^"`$]*"' + "|" + r"'IdentityFile=[^']*'" + r"))(?=\s|$)")
            checks = [(value[:named] + _re.sub(identity, "", value[named:end]) + value[end:]).strip()]
            spoken = [token for token, _ in tokens]
            for index in range(start + 1, len(spoken)):
                command = _option_command(spoken, index, spoken[index])
                if command:
                    checks.append(command)
            return checks


        def _check_transports(command: str, protected, depth: int):
            # rsync, ssh, scp, sftp, git and pagers run some values as commands on this computer, so those get
            # the same checks as any command. Quotes and escapes inside a name do not change it.
            import re as _re
            plain = _re.sub("[\"'\\\\`^]", "", command).lower()
            values = []
            if "rsync" in plain:
                values += _rsync_transports(command)
            if any(name in plain for name in ("proxycommand", "localcommand", "knownhostscommand", "git", "pager",
                                              "editor", "visual", "askpass")):
                values += _ssh_and_git_commands(command)
            texts = [text for value in dict.fromkeys(values) for text in _transport_checks(value)]
            texts = [text for text in dict.fromkeys(texts) if text.strip() not in ("", "ssh")]
            if texts and (depth >= 3 or len(texts) > 64):
                return ("nesting", "Blackbox blocked this call: it contains a nested or very complex command that the guard cannot inspect.")
            for text in texts:
                result = _check_command_safety({"command": text}, protected, depth + 1)
                if result is not None:
                    return result
            return None


        def _check_command_safety(args, protected=None, transport_depth: int = 0):
            injection = "" if _is_non_executable_doc_or_test_edit(args) else _axiom_injection(args)
            if injection:
                return ("injection-heuristic", "Blackbox blocked this call: prompt-injection phrasing in the tool arguments.")
            command_text = _command_text(args)
            arg_path = _arg_path(args)
            store = _sensitive_store(command_text)
            if not store:
                store = _sensitive_store(arg_path)
            if store:
                return ("credential-store", f"Blackbox blocked this call: it accesses a credential store ({store}).")
            if protected is None:
                protected = _load_protected_paths()
            if arg_path:
                norm_arg = _normalize_command(arg_path)
                tokens = _protected_tokens(protected)
                words = norm_arg.replace("\\", " ").replace("/", " ").replace('"', " ").replace("'", " ").split()
                if _any_word_matches(words, tokens) or _glob_hits(norm_arg, tokens):
                    return ("protected-path", "Blackbox blocked this call: it accesses a protected path.")
            if not command_text:
                return None
            if _UNINSPECTABLE_SEGMENT in _split_shell_segments(command_text):
                # Blocked either way. A known risky shape keeps its more specific label.
                escalation = _escalation_risk(command_text)
                if escalation:
                    return ("escalation", f"Blackbox blocked this call: {escalation}.")
                if len(command_text) > _MAX_COMMAND_LENGTH:
                    return ("nesting", "Blackbox blocked this call: the command is too long for the guard to inspect.")
                return ("nesting", "Blackbox blocked this call: it contains a nested or very complex command that the guard cannot inspect.")
            transport = _check_transports(command_text, protected, transport_depth)
            if transport is not None:
                return transport
            if _tampers_with_guard(command_text):
                return ("tamper", "Blackbox blocked this call: it modifies the local guard.")
            if _disables_guard(command_text):
                return ("tamper", "Blackbox blocked this call: it stops or disables the local guard.")
            if _deletes_protected(command_text, protected):
                return ("delete", "Blackbox blocked this call: it deletes a protected path.")
            if _reads_protected(command_text, protected):
                return ("read", "Blackbox blocked this call: it reads a protected path.")
            if _hidden_path_read(command_text, protected):
                return ("read", "Blackbox blocked this call: it reads a protected path through a hidden path form.")
            if _tampers_with_protected(command_text, protected):
                return ("permissions", "Blackbox blocked this call: it changes ownership or permissions of a protected path.")
            if _writes_protected(command_text, protected):
                return ("write", "Blackbox blocked this call: it modifies a protected path.")
            if _exfiltrates_protected(command_text, protected):
                return ("exfiltration", "Blackbox blocked this call: it uploads a file from a protected path.")
            if _executes_protected(command_text, protected):
                return ("execution", "Blackbox blocked this call: it launches a file from a protected path.")
            escalation = _escalation_risk(command_text)
            if escalation:
                return ("escalation", f"Blackbox blocked this call: {escalation}.")
            return None
        """;
}
