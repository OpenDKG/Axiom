// Pure policy for re-creating the NEFilterManager configuration. Kept separate so the Swift
// unit tests can compile and check it without NetworkExtension/SystemExtensions.
//
// An NEFilterManager configuration is bound to the code signature of the app that saved it. The
// activation host is re-signed whenever the extension or host changes, so a replacement always
// needs a fresh configuration; `--reset-filter` forces the same path when nothing was replaced.

func filterRefreshRequired(explicitReset: Bool, replaced: Bool) -> Bool {
    explicitReset || replaced
}
