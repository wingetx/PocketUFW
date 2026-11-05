package io.github.pocketufw

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * SystemUI keeps an active tile's last state across a reboot and doesn't bind the
 * service afterwards, so a tile can stay green with the firewall off. This only
 * asks SystemUI to bind it once, so that it re-reads its cache and finds it belongs
 * to an earlier boot. No root, and nothing stays running.
 */
internal class BootTileReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) TileStatusStore.request(context)
    }
}
