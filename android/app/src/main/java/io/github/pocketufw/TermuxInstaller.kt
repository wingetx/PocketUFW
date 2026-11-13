package io.github.pocketufw

import android.content.Context
import java.security.MessageDigest

internal const val TERMUX_HELPER_ASSET = "termux/pufw"

internal fun bundledTermuxInstallCommand(context: Context): String {
    val helper = context.assets.open(TERMUX_HELPER_ASSET).use { it.readBytes() }
    check(helper.isNotEmpty()) { "Bundled helper is empty" }
    val digest = MessageDigest.getInstance("SHA-256").digest(helper)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
    return termuxInstallCommand(context.applicationInfo.sourceDir, digest)
}

private fun shellQuote(value: String) = "'" + value.replace("'", "'\"'\"'") + "'"

/** Generate text only. Termux executes it as its own UID; the app never installs or requests root. */
internal fun termuxInstallCommand(apkPath: String, digest: String): String {
    require(apkPath.startsWith("/") && apkPath.none { it.code < 32 || it.code == 127 })
    require(digest.matches(Regex("[0-9a-f]{64}")))
    val script = listOf(
        "set -eu",
        "pufw_fail() { printf '%s\\n' \"\$1\" >&2; exit 1; }",
        "for pufw_tool in id unzip sha256sum mktemp chmod mv rm; do command -v \"\$pufw_tool\" >/dev/null 2>&1 || pufw_fail \"Missing command: \$pufw_tool. Install it in Termux and retry.\"; done",
        "pufw_uid=\$(id -u) || pufw_fail 'Could not confirm the Termux user.'",
        "case \"\$pufw_uid\" in ''|*[!0-9]*) pufw_fail 'Could not confirm the Termux user.' ;; 0) pufw_fail 'Run this command in normal Termux, without su.' ;; esac",
        "case \"\${PREFIX:-}\" in /*) ;; *) pufw_fail 'Termux PREFIX is unavailable.' ;; esac",
        "[ -d \"\$PREFIX/bin\" ] && [ -w \"\$PREFIX/bin\" ] || pufw_fail 'Termux command directory is unavailable.'",
        "umask 077",
        "pufw_tmp=''",
        "trap '[ -z \"\$pufw_tmp\" ] || rm -f -- \"\$pufw_tmp\"' 0",
        "trap 'exit 1' 1 2 15",
        "pufw_tmp=\$(mktemp \"\$PREFIX/bin/.pufw.XXXXXX\") || pufw_fail 'Could not create a temporary helper.'",
        "unzip -p ${shellQuote(apkPath)} assets/$TERMUX_HELPER_ASSET > \"\$pufw_tmp\" || pufw_fail 'Could not read the APK helper. Copy a fresh installation command from PocketUFW.'",
        "[ -s \"\$pufw_tmp\" ] || pufw_fail 'The extracted helper is empty.'",
        "pufw_sum=\$(sha256sum < \"\$pufw_tmp\") || pufw_fail 'Could not verify the helper.'",
        "[ \"\${pufw_sum%% *}\" = ${shellQuote(digest)} ] || pufw_fail 'Helper integrity check failed; existing helper preserved.'",
        "chmod 700 -- \"\$pufw_tmp\" || pufw_fail 'Could not set helper permissions.'",
        // Same-directory rename commits only verified bytes, without following a destination symlink.
        "mv -fT -- \"\$pufw_tmp\" \"\$PREFIX/bin/pufw\" || pufw_fail 'Could not replace the helper.'",
        "pufw_tmp=''",
        "printf '%s\\n' 'pufw installed. Run pufw in Termux.' || :"
    ).joinToString("; ")
    return "sh -c ${shellQuote(script)}"
}
