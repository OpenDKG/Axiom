// AxiomFilter — system extension entry point.
//
// The Network Extension runtime instantiates FilterDataProvider (named in the
// bundle's Info.plist under NetworkExtension/NEProviderClasses) when the
// content filter configuration is enabled.

import Foundation
import NetworkExtension
import os

Logger(subsystem: FilterLog.subsystem, category: "filter")
    .notice("AxiomFilter system extension starting, version \(FilterDataProvider.version, privacy: .public)")

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()
