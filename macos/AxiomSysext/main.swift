// axiom-sysext — command-line front end for SysextCore.swift.
//
// Usage: axiom-sysext <command> [--timeout SECONDS] [--no-wait] [--force] [--reset-filter]
//
//   activate    submit the system extension activation request (install/upgrade),
//               then save and enable the NEFilterManager content filter configuration.
//               An installed extension is replaced when its version/build or cdhash differ
//               from the embedded one; --force always replaces.
//               --no-wait: exit 3 as soon as macOS asks for user approval
//               (default: wait up to --timeout seconds, 120 by default, for approval)
//               --reset-filter: remove and re-create the filter configuration (always done
//               for ad hoc signed builds, whose signature changes with every rebuild)
//   deactivate  remove the filter configuration, then request extension deactivation
//   enable      enable the filter configuration only (extension must be activated)
//   disable     disable the filter configuration only (extension stays installed)
//   status      report extension and filter state (no changes, no prompts)
//
// Output: exactly one JSON object on stdout. Human-readable progress goes to stderr.
// Exit codes (ExitCode in SysextCore.swift): 0 ok, 1 error, 2 timeout, 3 waiting for user
// approval, 4 reboot required, 64 usage.

import Foundation

let usage = "usage: axiom-sysext activate|deactivate|enable|disable|status [--timeout SECONDS] [--no-wait] [--force] [--reset-filter]"

func printAndExit(_ result: SysextResult) -> Never {
    FileHandle.standardOutput.write(Data((result.json + "\n").utf8))
    exit(result.code.rawValue)
}

func usageExit(_ command: String, code: ExitCode) -> Never {
    let r = SysextResult(command: command, progress: { _ in }, completion: { _ in })
    r.finish(code, state: "usage", message: usage)
    printAndExit(r)
}

var args = Array(CommandLine.arguments.dropFirst())
let commandName = args.isEmpty ? "status" : args.removeFirst()
var timeout = defaultTimeout
var timeoutGiven = false
var wait = true
var force = false
var resetFilter = false
while !args.isEmpty {
    let arg = args.removeFirst()
    switch arg {
    case "--timeout":
        guard let v = args.first.flatMap(TimeInterval.init), v > 0 else { usageExit(commandName, code: .usage) }
        args.removeFirst()
        timeout = v
        timeoutGiven = true
    case "--no-wait":
        wait = false
    case "--force":
        force = true
    case "--reset-filter":
        resetFilter = true
    default:
        usageExit(commandName, code: .usage)
    }
}

let command: SysextCommand
switch commandName {
case "activate": command = .activate(force: force, wait: wait, resetFilter: resetFilter)
case "deactivate": command = .deactivate
case "enable": command = .enable
case "disable": command = .disable
case "status": command = .status
case "-h", "--help", "help": usageExit(commandName, code: .ok)
default: usageExit(commandName, code: .usage)
}
// status never prompts; keep it snappy unless the caller asked otherwise.
if case .status = command, !timeoutGiven { timeout = 15 }

runSysextCommand(command, queue: .main, timeout: timeout,
                 progress: { FileHandle.standardError.write(Data(("axiom-sysext: " + $0 + "\n").utf8)) },
                 completion: { printAndExit($0) })
dispatchMain()
