# Switchyard

A firewall and ad blocker for Android that runs entirely on your phone. No root needed.

It works by acting as a local VPN, so every app's traffic passes through it first. Nothing is sent to a server we run.

## What it does

- **Private DNS for every app.** All lookups go over an encrypted connection to the provider you pick (Cloudflare, Quad9, AdGuard, Google, or your own). Apps can't sneak around it.
- **Block apps from the internet.** Flip a switch per app.
- **Block ads and trackers.** Pick from popular block lists, or add your own.
- **See what's happening.** The Activity screen shows which apps connect where and what got blocked. From there you can always allow or always block a site.
- **Get around censorship.** Optional tricks that make it harder for networks to see or block the sites you visit.
- **Route through a proxy or WireGuard.** Send all apps, or just the ones you choose.
- **Stay on your Tailscale network.** Sign in once and every app can reach your tailnet devices, with no need for the Tailscale app. You can also send apps through one of your exit nodes.

## Getting started

1. Install the APK.
2. Open the app and tap the big power button. Android will ask you to allow a VPN; say yes.
3. If the app asks to run in the background, tap the notice and allow it. Otherwise Android may stop the filter to save battery.

Optional: to have the filter start on its own at boot and come back if it's stopped, go to Android's **Settings → Network → VPN**, tap the gear next to Switchyard and turn on **Always-on VPN**. The home screen then shows **Always-on**.

## Good to know

- **Only one VPN at a time.** Android doesn't allow two, so this can't run next to another VPN app. Use the WireGuard or Tailscale option instead.
- **Turn off Android's own Private DNS** (or set it to Automatic) if it's set to a specific provider. The app warns you if it is.
- **Block lists update daily** while the filter runs, or right away with **Update lists now**.
- **Changes to blocked sites take a few minutes** for apps that already looked up the address.
- **Some DNS providers block ads themselves** (AdGuard DNS, for example). An "always allow" rule can't undo that; pick a different provider.

## Building it yourself

You need Android Studio (for the SDK and NDK), Go, and `gomobile` (`go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init`).

```sh
./build-core.sh          # builds the Go engine
./gradlew installDebug   # builds and installs the app
```

Developer notes are in [AGENTS.md](AGENTS.md).

## License

GNU General Public License v3. See [LICENSE](LICENSE).
