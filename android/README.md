# Hashflow Fleet Command — Android APK

The dashboard in `web/` is a **Progressive Web App**: on any Android phone you
can simply open it in Chrome and choose **“Install app”** — it gets an icon,
runs fullscreen, and works offline. That is the zero-setup path and needs no
build tools at all.

This directory documents the **native APK** path (a Capacitor wrapper around
the same web app), for distribution outside a browser.

## Why a wrapper, not a rewrite?

The UI is a single dependency-free web bundle. Capacitor wraps it into a real
Android package (`.apk` / `.aab`) with the app icon, splash, and standalone
display — one codebase, identical behavior on Android/iOS/desktop browsers.

> **Note:** Google Play policy only allows apps that *remotely manage*
> cryptocurrency mining (not mine on-device). Hashflow Fleet Command is a
> management console — miners run on your own computers; the app monitors and
> controls them. Do not embed on-device mining in the APK.

## Build (run on a machine with Android tooling)

```bash
./scripts/build_apk.sh            # debug APK, side-loadable
./scripts/build_apk.sh release    # release APK (then sign with apksigner)
```

The script checks prerequisites (Node 18+, JDK 17+, `ANDROID_HOME`), installs
Capacitor locally, generates `android/app/`, and runs Gradle. Full details and
troubleshooting: `scripts/build_apk.sh` header comments.

## What ships in the package

| Item | Source |
|---|---|
| App name / ID | `capacitor.config.json` (`io.hashflow.fleetcommand`) |
| Icon (512, adaptive) | `web/icons/icon-512.png` |
| Theme / splash colors | `#0B0E13` (mission-control charcoal) |
| UI bundle | `web/` (no build step, no node_modules at runtime) |
| Data source | Demo simulator out of the box; live data via your Fleet Command server URL |

## Pointing the app at a live fleet

The app probes `/api/health` on its own origin. To manage a real fleet from
the phone, either:

1. Run the Fleet Command server on your mining host and open its URL in the
   app's browser/WebView (LAN or reverse proxy with TLS), or
2. Use the PWA and add the server URL as a home-screen shortcut per host.

Recommended: serve over HTTPS via a reverse proxy (Caddy/nginx) — the WebView
and service worker treat mixed content strictly by design.
