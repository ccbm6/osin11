package com.personal.recon

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

class MainActivity : FragmentActivity() {
    private var unlocked by mutableStateOf(false)
    private var lockMsg by mutableStateOf("")
    private var prompting = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // منع لقطات الشاشة وإخفاء المعاينة في قائمة التطبيقات الأخيرة
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(Modifier.fillMaxSize()) {
                    if (unlocked) AppRoot()
                    else Column(
                        Modifier.fillMaxSize().padding(24.dp),
                        verticalArrangement = Arrangement.Center,
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text("التطبيق مقفل", style = MaterialTheme.typography.titleLarge)
                        if (lockMsg.isNotBlank()) {
                            Spacer(Modifier.height(8.dp))
                            Text(lockMsg, style = MaterialTheme.typography.bodySmall)
                        }
                        Spacer(Modifier.height(16.dp))
                        Button(onClick = { authenticate() }) { Text("فتح") }
                    }
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        if (!unlocked) authenticate()
    }

    override fun onStop() {
        super.onStop()
        unlocked = false // يقفل عند الخروج من التطبيق
    }

    private fun authenticate() {
        if (prompting) return
        prompting = true
        val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    prompting = false; lockMsg = ""; unlocked = true
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    prompting = false; lockMsg = errString.toString()
                }
            })
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Recon")
            .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            .build()
        try { prompt.authenticate(info) } catch (e: Exception) {
            prompting = false; lockMsg = "اضبط قفل الشاشة (بصمة/رمز) على الهاتف أولاً"
        }
    }
}
