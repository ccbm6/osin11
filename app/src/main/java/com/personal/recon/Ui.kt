package com.personal.recon

import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private fun share(ctx: Context, text: String) {
    val i = Intent(Intent.ACTION_SEND).apply { type = "text/plain"; putExtra(Intent.EXTRA_TEXT, text) }
    ctx.startActivity(Intent.createChooser(i, null))
}

@Composable
fun AppRoot(vm: Vm = viewModel()) {
    var tab by rememberSaveable { mutableStateOf(0) }
    var settings by remember { mutableStateOf(false) }
    val tabs = listOf("🌐" to "نطاقات", "✉" to "بريد", "ℹ" to "معلومات", "🛰" to "Shodan", "🗂" to "السجل")

    Scaffold(bottomBar = {
        NavigationBar {
            tabs.forEachIndexed { i, (icon, label) ->
                NavigationBarItem(
                    selected = tab == i, onClick = { tab = i },
                    icon = { Text(icon) }, label = { Text(label, maxLines = 1) }
                )
            }
        }
    }) { pad ->
        Column(Modifier.padding(pad).padding(12.dp)) {
            if (tab < 4) {
                TargetBar(vm) { settings = true }
                Spacer(Modifier.height(8.dp))
            }
            when (tab) {
                0 -> SubsTab(vm)
                1 -> MailsTab(vm)
                2 -> InfoTab(vm)
                3 -> ShodanTab(vm)
                else -> HistoryTab(vm)
            }
        }
    }
    if (settings) KeysDialog(vm) { settings = false }
}

@Composable
private fun TargetBar(vm: Vm, onSettings: () -> Unit) {
    Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
        OutlinedTextField(
            value = vm.target, onValueChange = { vm.target = it },
            label = { Text("الهدف (example.com)") }, singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
            modifier = Modifier.weight(1f)
        )
        TextButton(onClick = onSettings) { Text("⚙") }
    }
}

@Composable
private fun ResultPane(t: ToolState, type: String, vm: Vm) {
    val ctx = LocalContext.current
    if (t.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
    if (t.status.isNotBlank()) Text(t.status, style = MaterialTheme.typography.bodySmall)
    if (t.lines.isNotEmpty()) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { vm.save(type, t) }) { Text("حفظ مشفّراً") }
            OutlinedButton(onClick = { share(ctx, t.lines.joinToString("\n")) }) { Text("مشاركة") }
        }
    }
    SelectionContainer {
        LazyColumn(Modifier.fillMaxSize()) {
            items(t.lines) {
                Text(it, Modifier.padding(vertical = 2.dp), fontFamily = FontFamily.Monospace, fontSize = 13.sp)
            }
        }
    }
}

@Composable
private fun SubsTab(vm: Vm) {
    var live by rememberSaveable { mutableStateOf(true) }
    Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
        Checkbox(live, { live = it }); Text("الأسماء الحيّة فقط (تحليل DNS)")
    }
    Button(onClick = { vm.runSubs(live) }, enabled = !vm.subs.busy, modifier = Modifier.fillMaxWidth()) {
        Text("بحث عن النطاقات الفرعية")
    }
    ResultPane(vm.subs, "نطاقات", vm)
}

@Composable
private fun MailsTab(vm: Vm) {
    Button(onClick = { vm.runEmails() }, enabled = !vm.mails.busy, modifier = Modifier.fillMaxWidth()) {
        Text("جمع البريد المنشور")
    }
    ResultPane(vm.mails, "بريد", vm)
}

@Composable
private fun InfoTab(vm: Vm) {
    Button(onClick = { vm.runInfo() }, enabled = !vm.info.busy, modifier = Modifier.fillMaxWidth()) {
        Text("DNS + WHOIS")
    }
    ResultPane(vm.info, "معلومات", vm)
}

@Composable
private fun ShodanTab(vm: Vm) {
    Button(onClick = { vm.runShodan() }, enabled = !vm.shodan.busy, modifier = Modifier.fillMaxWidth()) {
        Text("استعلام Shodan (نطاق أو IP)")
    }
    ResultPane(vm.shodan, "Shodan", vm)
}

@Composable
private fun HistoryTab(vm: Vm) {
    val ctx = LocalContext.current
    var open by remember { mutableStateOf<Long?>(null) }
    val fmt = remember { SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US) }
    if (vm.history.isEmpty()) {
        Text("لا توجد نتائج محفوظة بعد")
        return
    }
    LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(vm.history, key = { it.id }) { s ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    Text("${s.type} • ${s.target}", style = MaterialTheme.typography.titleSmall)
                    Text("${s.lines.size} سطر • ${fmt.format(Date(s.id))}", style = MaterialTheme.typography.bodySmall)
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        TextButton(onClick = { open = if (open == s.id) null else s.id }) {
                            Text(if (open == s.id) "إخفاء" else "عرض")
                        }
                        TextButton(onClick = { share(ctx, s.lines.joinToString("\n")) }) { Text("مشاركة") }
                        TextButton(onClick = { vm.delete(s) }) { Text("حذف") }
                    }
                    if (open == s.id) {
                        SelectionContainer {
                            Text(s.lines.joinToString("\n"), fontFamily = FontFamily.Monospace, fontSize = 13.sp)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun KeysDialog(vm: Vm, onClose: () -> Unit) {
    var s by remember { mutableStateOf(vm.shodanKey) }
    var h by remember { mutableStateOf(vm.hunterKey) }
    var v by remember { mutableStateOf(vm.vtKey) }
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("مفاتيح API (مخزّنة مشفّرة)") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                KeyField("Shodan", s) { s = it }
                KeyField("Hunter.io", h) { h = it }
                KeyField("VirusTotal", v) { v = it }
            }
        },
        confirmButton = { TextButton(onClick = { vm.saveKeys(s, h, v); onClose() }) { Text("حفظ") } },
        dismissButton = { TextButton(onClick = onClose) { Text("إلغاء") } }
    )
}

@Composable
private fun KeyField(label: String, value: String, onChange: (String) -> Unit) {
    OutlinedTextField(
        value = value, onValueChange = onChange, label = { Text(label) }, singleLine = true,
        visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth()
    )
}
