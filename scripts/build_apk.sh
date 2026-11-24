#!/usr/bin/env bash
# Build the Hashflow Fleet Command Android APK (Capacitor wrapper around the
# web app in web/).
#
# Prerequisites (one-time, on a normal dev machine — NOT needed to use the
# dashboard in a browser):
#   * Node.js 18+          (https://nodejs.org)
#   * JDK 17+              (e.g. `brew install temurin` / apt install openjdk-17-jdk)
#   * Android SDK          (install Android Studio, or `sdkmanager` cmdline tools)
#     then: export ANDROID_HOME=~/Android/Sdk  and add platform-tools to PATH
#
# Usage:
#   ./scripts/build_apk.sh              # debug APK (side-loadable)
#   ./scripts/build_apk.sh release      # release APK (unsigned; sign with apksigner)
#
# Output: android/app/build/outputs/apk/.../app-debug.apk
set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-debug}"

echo "==> Checking prerequisites"
command -v node >/dev/null || { echo "Node.js 18+ required"; exit 1; }
command -v java >/dev/null || { echo "JDK 17+ required"; exit 1; }
if [ -z "${ANDROID_HOME:-}" ] && [ -z "${ANDROID_SDK_ROOT:-}" ]; then
  echo "Set ANDROID_HOME (or ANDROID_SDK_ROOT) to your Android SDK path"; exit 1
fi

echo "==> Installing Capacitor toolchain (local, no global installs)"
npm install --no-fund --no-audit @capacitor/core @capacitor/cli @capacitor/android

echo "==> Generating native Android project"
npx cap add android 2>/dev/null || echo "(android project already exists)"
npx cap sync android

echo "==> Building APK ($MODE)"
cd android
if [ "$MODE" = "release" ]; then
  ./gradlew assembleRelease
  echo "==> Done: android/app/build/outputs/apk/release/"
  echo "    Sign it with: apksigner sign --ks your.keystore app-release-unsigned.apk"
else
  ./gradlew assembleDebug
  echo "==> Done: android/app/build/outputs/apk/debug/app-debug.apk"
  echo "    Install it:   adb install app-debug.apk   (or copy to the phone and open)"
fi
