# Switchyard

Android firewall built on `VpnService`, in the spirit of RethinkDNS. All device traffic goes
through a local tun; a Go engine decides what happens to each flow.

Internal names (`snf.app`, Go module `snf/core`, `SNF_*` env vars, prefs file `snf`) are the old codename; leave them.

What the app does:
- **Secure DNS for every app.** Every query on port 53, to any IP, is answered by us and forwarded over DoH, DoT or DoQ. DoT/DoQ (:853), DoH to well-known resolver IPs, and lookups of public DoH hostnames are blocked, so apps can't bypass it.
- **Per-app firewall.** Each flow is matched to its app (UID), and blocked apps get a RST or a dropped packet.
- **Ad blocking.** Domain lists (hosts, plain domains or adblock `||x^`) are downloaded and matched on the device. Blocked names get NXDOMAIN.
- **Anti-censorship.** Optional tricks: split the TLS ClientHello inside the SNI, fragment the TLS record, mangle the HTTP Host header, block QUIC.
- **Activity log and your rules.** An optional in-memory log records each decision (app, domain, IP, allow/block, and why). Your own domain allow/block rules can be added straight from a log entry.
- **Optional upstream.** Traffic can go through a SOCKS5 or HTTP CONNECT proxy (TCP only), or through userspace WireGuard (TCP and UDP). Saved WireGuard profiles can be switched live.
- **Tailscale.** An embedded tsnet node reaches tailnet IPs (100.64.0.0/10, fd7a:115c:a1e0::/48) for every app. It's its own switch: tailnet IPs go to Tailscale first, everything else follows the route mode, so it works alongside WireGuard or a proxy. Route mode "exit" sends the routed apps' internet through a Tailscale exit node instead; `tsNode.dial` refuses anything tsnet has no Tailscale route for, so a missing or offline exit node fails closed rather than going direct. Optional "Tailscale DNS" asks the tailnet's resolver first and falls back to the chosen provider.

## Layout

```
core/                 Go engine, bound to Java with gomobile -> app/libs/core.aar (git-ignored)
  tunnel.go           (linux) Start/Reconfigure/Stop, gVisor netstack on the tun fd, TCP/UDP forwarders, DNS serving
  routing.go          config JSON -> immutable `state` (newState), per-flow routing, dnsDecision (rule precedence)
  events.go           in-memory activity log (last 2000), IP->domain memory
  wireguard.go        wg-quick parser -> UAPI, wireguard-go on its own netstack, WgHandshakeAge
  tailscale.go        tsnet node (tsFor), tailnet routing, Tailscale DNS with fallback, TsStatus/TsPeers/TsLogin/TsLogout
  blocklist.go        domainSet: list parsing + suffix lookup
  desync.go           SNI split, TLS record fragmentation, HTTP Host tricks (pure byte functions)
  dialer.go           direct / SOCKS5 / HTTP CONNECT dialers
  routes.go           RoutesExcluding: tun routes minus the local network
  bypass.go           known DoH/DoT hostnames and resolver IPs
  callback.go         Callback interface implemented in Kotlin (UidFor, Log)
app/src/main/java/snf/app/
  FilterVpnService.kt builds the tun, hands the fd to core, implements Callback; notification with Stop/Start
  FilterTile.kt       Quick Settings toggle
  Settings.kt         SharedPreferences "snf" -> configJson(); presets; WireGuard profiles; list downloads
  MainActivity.kt     theme (Material You), Tab enum, nav scaffold
  HomeScreen.kt       power button, status notices, summary rows
  Screens.kt          shared row components + DNS / Apps screens, Privacy menu and its sub-pages
  WireGuardScreen.kt  WireGuard status, profile list, config editor
  TailscaleScreen.kt  Tailscale switch, status and sign-in, device list, collapsible control URL and auth key
  ActivityScreen.kt   log view (polls Core.events once a second), your rules, per-entry action sheet
build-core.sh         rebuilds app/libs/core.aar
```

## Build and test

- **Go core:**
  - `cd core && go test ./...` runs on macOS, because the tests avoid linux-only files.
  - `GOOS=android GOARCH=arm64 go vet ./...` also checks `tunnel.go`.
- **AAR:** run `./build-core.sh` after *any* Go change; Gradle doesn't rebuild it. It needs `gomobile` in `$(go env GOPATH)/bin`, plus the NDK.
- **App:**
  - `./gradlew installDebug`.
  - The JDK comes from `org.gradle.java.home` in `gradle.properties`, which points at Android Studio's bundled JBR, because the system JDK is too new for AGP.
- **CI:** `.github/workflows/build.yml` runs Go tests, builds the AAR, then makes a debug APK on pushes and PRs. Dependabot opens weekly update PRs for Go modules, Gradle and Actions. A `vX.Y.Z` tag (e.g. `v0.1.3`) sets `versionName` to `X.Y.Z` and `versionCode` to `X*1000000 + Y*1000 + Z`, then builds signed release APKs (arm64-v8a, x86_64 and universal) and attaches them to a GitHub release. Signing reads `SNF_KEYSTORE`, `SNF_KEYSTORE_PASSWORD`, `SNF_KEY_ALIAS` and `SNF_KEY_PASSWORD` from the environment, so it works the same locally. CI fills these from the secrets `KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`, `KEY_ALIAS` and `KEY_PASSWORD`.
- **Release APKs:** R8 is on, and core.aar ships its own keep rules (`go.**`, `snf.**`). Native libs are stored compressed (about 10 MB per ABI APK instead of about 45 MB). To test a release build on the emulator without losing app data, sign it with `~/.android/debug.keystore` through the `SNF_*` variables (password `android`, alias `androiddebugkey`) and `adb install -r` the arm64 APK; the emulator is arm64 on Apple silicon.
- **Versions:** AGP 9.5 (built-in Kotlin, so no `kotlin-android` plugin), Kotlin 2.4, Compose BOM 2026.09, minSdk 29 (for `getConnectionOwnerUid`), compileSdk 37 (required by Compose), targetSdk 36.
- **On-device testing (emulator `emulator-5554`, Play image, so no root and no tcpdump):**
  - `adb shell appops set dev.ohaiibuzzle.switchyard ACTIVATE_VPN allow` skips the VPN consent dialog. Reinstalling stops the VPN; tap the power button again.
  - `adb shell` runs as `com.android.shell` (uid 2000). Its traffic goes through the VPN, so `curl` and `nc -u -q3 -W3` work as test clients. `ping` doesn't: the engine drops ICMP (except to the skipped local network).
  - `uiautomator dump` exposes merged Compose nodes. Empty text fields don't expose their label, so tap them by coordinates.
  - Settings can be read with `adb exec-out run-as dev.ohaiibuzzle.switchyard cat shared_prefs/snf.xml`. They can be written with `adb exec-in run-as dev.ohaiibuzzle.switchyard sh -c 'cat > shared_prefs/snf.xml'` after `am force-stop`.
  - The emulator's NAT re-joins TCP streams, so TCP segment splits can't be seen from the host. TLS record changes can.

## How it fits together

- **Our app excludes itself from the VPN** (`addDisallowedApplication(self)`). The engine's sockets therefore go straight out, with no `protect()` needed.
- **Local network:** with "Skip local network" (default off), the tun routes are everything except the LAN subnets, link-local, multicast and broadcast. `RoutesExcluding` in `routes.go` computes them, because `Builder.excludeRoute` needs Android 13. LAN traffic bypasses app blocking and the log.
- **IPv6:** the VPN only advertises v6 if the underlying network has a global v6 address. Otherwise Android blocks v6 for VPN users and apps fall back to v4 fast.
- **Settings to engine:**
  - `Settings.configJson()` produces one JSON string, and Go parses it into an immutable `state`, swapped atomically.
  - `Reconfigure` applies changes live; existing flows keep their old decision.
  - The WireGuard tunnel is reused when its config text is unchanged, so unrelated toggles don't drop VPN connections.
- **TCP flows:** the engine dials the destination *before* accepting the app's connection, so a failed dial becomes a clean RST. Desync only touches the client's first flight of data.
- **Logging:**
  - It's off unless `log` is set in the config; then `record()` returns after one atomic load.
  - Kotlin polls `Events(afterSeq)`. Sequence numbers never reset within the process, so a VPN restart doesn't confuse the poller. `Stop()` clears the log.
- **Domain decisions:** `dnsDecision` applies, in order: your allow rule, your block rule, ad lists, the DNS-bypass list. Rules act **only at DNS time**, so apps holding a cached answer keep connecting until the TTL expires.
- **WireGuard** handshakes lazily, so `startWG` sends one keepalive per peer to bring it up straight away.
- **UI state:**
  - `Settings` exposes typed properties (`s.adblock`, `s.blockedUids`, …). Every read touches a Compose state counter that a prefs listener bumps, so composables recompose on any settings change. No manual re-keying.
  - Multi-key writes (`setDns`, `addRule`, `removeRule`, `saveWg`) are one `edit()`.
  - Screens just write `Settings`. Its prefs listener calls `FilterVpnService.reconfigure`, which merges a burst of writes into one reconfigure. Changes outside prefs (a list download) call it directly.
  - Engine start, reconfigure and stop all run on one single-thread executor in `FilterVpnService`, so they apply in order. `starting`, `running` and `lastError` are Compose state; the UI reads them directly.
  - Tabs are the `Tab` enum. `rememberSaveableStateHolder` keeps each tab's scroll position. Sub-pages (Activity, Ad blocking, Disguise, Route) are the `Page` enum, opened over a tab with a back arrow.

## Gotchas

- **`fdbased` doesn't close the tun fd;** `Stop()` closes it.
- **Linux-only code:** `tunnel.go` is `//go:build linux` because gVisor's fdbased only builds on Linux. Logic you want to unit-test on macOS goes in untagged files.
- **gomobile dependency:** `go mod tidy` used to drop `golang.org/x/mobile`. It's now pinned with a `tool` line in `core/go.mod`; keep it.
- **`AAPT2 Daemon startup failed`:** run `./gradlew --stop` and retry.
- **WireGuard config storage:** configs (which include private keys) live in prefs; `allowBackup="false"` keeps them out of cloud backups. The pre-profiles `wgConf` key is removed on the next profile write.
- **Blocking DNS providers:** AdGuard DNS (and similar) block ads themselves and answer with `0.0.0.0`. An "allow" rule can't override that; switch provider.
- **Android Private DNS** set to a specific hostname conflicts with our :853 block, so Home shows a warning.
- **Tailscale on Android:**
  - Apps can't call `net.Interfaces`, so `tailscale.go` registers its own getter. Tailscale's `androidbin` fallback skips cgo builds like ours.
  - There's no `$HOME` or `$TMPDIR`, so `TS_LOGS_DIR` must point at the state dir, or tsnet panics on start.
  - `envknob.SetNoLogsNoSupport()` stops log uploads to Tailscale. Log buffers still rotate locally under `files/tailscale`.
  - tsnet can't see Android's DNS servers, so its resolver fails public names unless the tailnet sets global nameservers. That's why Tailscale DNS falls back to the provider.
- **`VpnService.isAlwaysOn`** is false until our tunnel is established, so read it after `establish()`, not in `onStartCommand`.

## Conventions

- **Commits:** Conventional Commits (`feat(core): …`, `fix(app): …`, `build: …`), short subjects, no long bodies.
- **Smallest change that fully works:** known limits get a `// shortcut: <limit>, <when to upgrade>` comment; list them with `grep -rn "shortcut:"`.
- **UI copy:** terse. Only add a subtitle when it says something the title can't (a choice, a status, or a surprising caveat).
- **Tests:** non-trivial logic leaves a test, especially byte-level protocol code and anything security-related.
