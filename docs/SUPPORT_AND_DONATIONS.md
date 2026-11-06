# Axiom — optional support and donations

This Draft branch stacks on #100 → #99 → #97 → #96. It adds a **Support** navigation destination. Do not merge into `main` until the parent PR chain is validated on Windows.

## Donation channels

- Buy Me a Coffee: externally hosted creator URL, HTTPS only, `buymeacoffee.com/{username}`.
- PayPal: externally hosted `paypal.me/{username}` link. This may display the recipient's profile name/city; the maintainer must review privacy and country eligibility.
- GitHub Sponsors: `github.com/sponsors/{account}` after the maintainer account actually participates in Sponsors.
- Crypto: configurable *public receiving addresses* for BTC on Bitcoin mainnet, ETH on Ethereum/Base/Polygon, or USDC on a specifically named EVM network. The UI displays the exact recipient address and chain and allows copying only; Axiom never stores keys, connects to wallets, signs transactions, checks balances or submits transfers.

## Where to configure recipients

Edit `src/Netpetra.UI/Resources/support-links.json` **before producing a release**. This resource is embedded in `Netpetra.UI.dll` and is not a per-user destination override. All values are intentionally empty in this Draft branch; the donation CTAs are disabled until the maintainer supplies *and verifies* a real recipient.

Example structure (illustrative only; never commit these placeholders as real receiving addresses):

```json
{
  "buyMeACoffeeUrl": "",
  "paypalUrl": "",
  "githubSponsorsUrl": "",
  "crypto": [
    { "currency": "BTC", "network": "Bitcoin mainnet", "address": "" },
    { "currency": "ETH", "network": "Ethereum mainnet", "address": "" },
    { "currency": "USDC", "network": "Base mainnet", "address": "" }
  ]
}
```

The validator rejects non-HTTPS donation links, unexpected sites/domains, user-info components, query strings, fragments and unsupported ports. A crypto address must match a supported syntax and explicitly declared network, but **syntax checks are not a substitute for checking the Bitcoin checksum/EIP-55 where applicable, wallet ownership, the USDC contract and receiving-chain compatibility**. A human maintainer should confirm recipients with a test transfer before release. When a link or address is missing/invalid, it is unavailable rather than silently linking to a vendor homepage or an unknown person.

Do not enter private keys, recovery phrases, wallet seed words, API secrets, account passwords, personal access tokens or any other credentials into this JSON or Git.

## Behavior and privacy

- The donation page is informational, non-blocking and never requests payment.
- Clicking a configured provider opens the external site through the OS browser; no embedded browser, payment flow, authentication or payment telemetry is added.
- A configured crypto address can only be copied to the local clipboard. The UI clearly names the network.
- Donations do not unlock or disable security features. No upsell dialogs, first-run payment requirements, intrusive reminders or automatic pop-ups are added.
- Brand text is used for recognition, but no unlicensed official PayPal/Buy Me a Coffee/GitHub image assets are embedded.

## Optional GitHub repository funding button

After the accounts are verified, the maintainer can optionally add an official `.github/FUNDING.yml` on the default branch, with documented fields such as `buy_me_a_coffee:`, `github:` and `custom:`. Do not create the real funding file with guessed usernames.

Reference: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/displaying-a-sponsor-button-in-your-repository

## Manual validation

1. Windows `dotnet restore Netpetra.sln --locked-mode`, `dotnet build Netpetra.sln -c Release --no-restore`, `dotnet test Netpetra.sln -c Release --no-build`.
2. Verify Support appears in the left navigation and does not break the app's existing pages.
3. With the empty JSON, all provider buttons are disabled and no crypto addresses are shown.
4. In an isolated test build, configure permitted links; confirm exact URL routes and browser handoff.
5. Try invalid schemes, ports, lookalike domains, embedded credentials and malformed crypto addresses. All must remain blocked.
6. Test crypto copy-only action and clipboard contention; test every theme, keyboard navigation, narrow window and screen reader labels.
7. Confirm app startup, IP Helper/SQLite/service, firewall policies and all agent sessions/config/junctions are untouched.

**Status:** Code authored, not compiled or smoke-tested in a Windows environment here.
