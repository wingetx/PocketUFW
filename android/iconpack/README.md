# PocketUFW Neon: a tiny standalone icon pack

One original transparent-background neon penguin, packaged separately from
Blaze Backless and from the PocketUFW firewall engine.

After installing its APK, long-press PocketUFW in Niagara, tap its icon,
choose PocketUFW Neon among installed icon packs, and select the penguin.
The pack uses conventional ADW/Nova-style appfilter.xml and drawable.xml
mapping. It declares no network, storage, root or other permissions
and has no launcher entry or background service.

The icon automatically maps to io.github.pocketufw.MainActivity.
This separate pack does not alter installed Blaze or Android firewall state.

Version 1.1 refreshes the Neon penguin with a muted shield-holding design.
The official companion APK is now built from the release variant and signed
with PocketUFW's dedicated release key; it can update in place on future versions.
Earlier debug-signed icon pack builds cannot update in place because Android
requires matching signatures. Uninstall the old **Neon icon pack only** and
install the newly signed companion APK, then reselect it in Niagara if needed.
Removing this icon pack does not touch PocketUFW or its kernel firewall rules.

Build: cd android && ./gradlew :iconpack:assembleRelease
Unsigned APK: android/iconpack/build/outputs/apk/release/iconpack-release-unsigned.apk

Original image: assets/branding/pocketufw-neon-penguin.png.
