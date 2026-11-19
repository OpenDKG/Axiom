// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Blackbox;

public static class BlackboxDashboardRuntime
{
    // The dashboard spawns sync as a separate Python process. Route that invocation back through
    // this launcher so its own subprocesses (including Git) inherit the Windows console handling.
    public static readonly string LauncherCode = """
        import argparse
        import os
        import sys

        if sys.stdout is None:
            sys.stdout = open(os.devnull, "w", encoding="utf-8")
        if sys.stderr is None:
            sys.stderr = open(os.devnull, "w", encoding="utf-8")

        if os.name == "nt":
            import inspect
            import subprocess

            _worker_flag = "--axiom-blackbox-sync-worker"
            _original_popen = subprocess.Popen.__init__
            _popen_signature = inspect.signature(_original_popen)

            def _silent_popen(self, *args, **kwargs):
                bound = _popen_signature.bind_partial(self, *args, **kwargs)
                argv = bound.arguments.get("args")
                if (isinstance(argv, (list, tuple)) and len(argv) >= 5
                        and argv[0] == sys.executable
                        and list(argv[1:5]) == ["-m", "hermes_cli.main", "blackbox", "sync"]):
                    bound.arguments["args"] = [
                        argv[0], os.path.abspath(__file__), _worker_flag, *argv[3:]
                    ]

                flags = bound.arguments.get("creationflags") or 0
                detached = getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
                new_console = getattr(subprocess, "CREATE_NEW_CONSOLE", 0x00000010)
                flags &= ~new_console
                if not (flags & detached):
                    flags |= subprocess.CREATE_NO_WINDOW
                bound.arguments["creationflags"] = flags

                startup = bound.arguments.get("startupinfo") or subprocess.STARTUPINFO()
                startup = startup.copy()
                startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startup.wShowWindow = subprocess.SW_HIDE
                bound.arguments["startupinfo"] = startup
                return _original_popen(*bound.args, **bound.kwargs)

            subprocess.Popen.__init__ = _silent_popen
            os.system = lambda cmd: subprocess.run(cmd, shell=True).returncode

            if sys.argv[1:2] == [_worker_flag]:
                import runpy

                del sys.argv[1]
                runpy.run_module("hermes_cli.main", run_name="__main__", alter_sys=True)
                raise SystemExit(0)

        from plugins.blackbox.dashboard import cmd_dashboard

        raise SystemExit(cmd_dashboard(argparse.Namespace(port=None)))
        """.ReplaceLineEndings("\n") + "\n";
}
