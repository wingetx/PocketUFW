package io.github.pocketufw

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

/**
 * Android tells an app nothing when it is being uninstalled, so this is the only moment
 * PocketUFW can clean up after itself. The firewall outlives an ordinary uninstall until
 * the next restart, which the row says up front.
 */
@Composable
internal fun TideRemoveSection(ui: TideUiState, actions: TideActions) {
    val state = ui.snapshot
    var removeOpen by rememberSaveable { mutableStateOf(false) }
    var anywayOpen by rememberSaveable { mutableStateOf(false) }
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        TideSettingLink("Remove PocketUFW",
            "Uninstalling without this leaves the firewall running until you restart the phone.") {
            if (!ui.busy && state.protection != FirewallClient.Protection.CHECKING) removeOpen = true
        }
        // The firewall can come back by another route, and then this is no longer true.
        if (ui.removal == TideRemoval.CLEAN && state.protection == FirewallClient.Protection.INACTIVE) {
            Column(Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                verticalArrangement = Arrangement.spacedBy(10.dp)) {
                TideNotice("The firewall is off and PocketUFW is still installed. ${ui.removalDetail}")
                OutlinedButton(onClick = actions.openAppInfo, enabled = !ui.busy, shape = TideActionShape,
                    modifier = Modifier.fillMaxWidth().heightIn(min = TideActionMinHeight)) {
                    Text("Open Android's app page")
                }
                TextButton(onClick = { actions.changeProtection(true) }, enabled = !ui.busy && state.rootReady,
                    modifier = Modifier.fillMaxWidth()) { Text("Turn firewall back on") }
            }
        }
        if (ui.removal == TideRemoval.INCOMPLETE) {
            Column(Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                verticalArrangement = Arrangement.spacedBy(10.dp)) {
                TideNotice(ui.removalDetail, true)
                OutlinedButton(onClick = actions.prepareUninstall, enabled = !ui.busy, shape = TideActionShape,
                    modifier = Modifier.fillMaxWidth().heightIn(min = TideActionMinHeight)) {
                    Text("Try again")
                }
                TextButton(onClick = { anywayOpen = true }, enabled = !ui.busy,
                    modifier = Modifier.fillMaxWidth()) { Text("Uninstall anyway") }
            }
        }
    }
    if (removeOpen) AlertDialog(containerColor = Background, tonalElevation = 0.dp,
        onDismissRequest = { removeOpen = false },
        title = { Text("Remove PocketUFW?") },
        text = { Text("This turns the firewall off now, removes PocketUFW's rules and Magisk boot files, " +
            "and checks they're gone. Rules from Android, VPNs and other apps aren't touched.\n\n" +
            "Android's app page opens next. Tap Uninstall there to finish.") },
        confirmButton = {
            TextButton(onClick = { removeOpen = false; actions.prepareUninstall() }, enabled = !ui.busy,
                modifier = Modifier.testTag("confirm-remove-pocketufw")) { Text("Remove and continue") }
        },
        dismissButton = { TextButton(onClick = { removeOpen = false }) { Text("Cancel") } })
    if (anywayOpen) AlertDialog(containerColor = Background, tonalElevation = 0.dp,
        onDismissRequest = { anywayOpen = false },
        title = { Text("Uninstall anyway?") },
        text = { Text("Any rules still in the kernel stay until you restart the phone, and PocketUFW " +
            "won't be there to change them. Boot files remove themselves at the next restart, " +
            "once Android confirms the app is gone.") },
        confirmButton = {
            TextButton(onClick = { anywayOpen = false; actions.openAppInfo() },
                modifier = Modifier.testTag("confirm-uninstall-anyway")) { Text("Open app page") }
        },
        dismissButton = { TextButton(onClick = { anywayOpen = false }) { Text("Cancel") } })
}
