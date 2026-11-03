# PocketUFW Neon: a tiny standalone icon pack

One original transparent-background neon penguin, packaged separately from
Blaze Backless and from the PocketUFW firewall engine.

After installing its APK, long-press PocketUFW in Niagara, tap its icon,
choose PocketUFW Neon among installed icon packs, and select the penguin.
The pack uses conventional ADW/Nova-style appfilter.xml and drawable.xml
mapping. It declares no network, storage, root or other permissions
and has no launcher entry or background service.

The icon automatically maps to io.github.pocketufw.alpha.MainActivity.
This separate pack does not alter installed Blaze or Android firewall state.

Build: cd android && ./gradlew :iconpack:assembleDebug
APK: android/iconpack/build/outputs/apk/debug/iconpack-debug.apk

Original image: assets/branding/pocketufw-neon-penguin.png.
