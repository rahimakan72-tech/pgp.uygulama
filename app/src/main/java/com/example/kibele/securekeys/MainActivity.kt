@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.kibele.securekeys

import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.TileMode
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.time.LocalDate
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

// ---------- Tema ----------
private val PurpleDeep = Color(0xFF0B0A13)
private val Purple01   = Color(0xFF1A1230)
private val Purple02   = Color(0xFF2B1F4A)
private val PurpleNeon = Color(0xFF9A6BFF)
private val PurpleGlow = Color(0xFFB388FF)
private val TextOnDark = Color(0xFFF2F2F7)

private val DarkScheme = darkColorScheme(
    primary = PurpleNeon, secondary = PurpleGlow,
    background = PurpleDeep, surface = Purple01,
    onPrimary = Color.White, onSecondary = Color.White,
    onBackground = TextOnDark, onSurface = TextOnDark
)

@Composable
private fun KibeleTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = DarkScheme, typography = Typography(), content = content)
}

private fun kibeleGradient(): Brush = Brush.verticalGradient(
    0f to PurpleDeep, 0.35f to Purple01, 0.7f to Purple02, 1f to PurpleDeep,
    tileMode = TileMode.Clamp
)

// ---------- Activity ----------
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { KibeleApp() }
    }
}

// ---------- App Lock (biyometrik/cihaz kilidi + zaman aşımı) ----------
private class AppLocker(
    private val activity: AppCompatActivity,
    private val timeoutMs: Long = 60_000L
) {
    /** Dışarıdan sadece okunur; set işlemleri içeride yapılır */
    var locked by mutableStateOf(true)
        private set
    private var lastStoppedAt: Long = 0L

    fun onStart() {
        // İlk açılışta veya time-out sonrası kilitli olsun
        if (lastStoppedAt == 0L || System.currentTimeMillis() - lastStoppedAt > timeoutMs) {
            locked = true
        }
    }
    fun onStop() { lastStoppedAt = System.currentTimeMillis() }

    private fun buildPromptInfo(): BiometricPrompt.PromptInfo {
        val b = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Kibele kilidi")
            .setSubtitle("Biyometrik veya cihaz kilidi ile doğrulayın")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            b.setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                        BiometricManager.Authenticators.DEVICE_CREDENTIAL
            )
        } else {
            b.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        }
        return b.build()
    }

    fun authenticate(onSuccess: () -> Unit, onFail: (String) -> Unit) {
        runCatching {
            val executor = ContextCompat.getMainExecutor(activity)
            val cb = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    locked = false; onSuccess()
                }
                override fun onAuthenticationError(code: Int, msg: CharSequence) { onFail(msg.toString()) }
                override fun onAuthenticationFailed() { onFail("Doğrulama başarısız") }
            }
            BiometricPrompt(activity, executor, cb).authenticate(buildPromptInfo())
        }.onFailure { onFail("Biyometri başlatılamadı: ${it.message ?: "bilinmiyor"}") }
    }
}

@Composable
private fun rememberAppLocker(timeoutMs: Long = 60_000L): AppLocker {
    val ctx = LocalContext.current as AppCompatActivity
    val locker = remember { AppLocker(ctx, timeoutMs) }
    val owner = LocalLifecycleOwner.current
    DisposableEffect(owner) {
        val obs = LifecycleEventObserver { _, e ->
            when (e) {
                Lifecycle.Event.ON_START -> locker.onStart()
                Lifecycle.Event.ON_STOP  -> locker.onStop()
                else -> {}
            }
        }
        owner.lifecycle.addObserver(obs)
        onDispose { owner.lifecycle.removeObserver(obs) }
    }
    return locker
}

@Composable
fun KibeleApp() {
    KibeleTheme {
        val locker = rememberAppLocker(timeoutMs = 90_000L)
        val nav = rememberNavController()
        val snack = remember { SnackbarHostState() }
        val scope = rememberCoroutineScope()

        Surface(Modifier.fillMaxSize()) {
            Box(Modifier.fillMaxSize().background(kibeleGradient())) {

                if (locker.locked) {
                    LockScreen(
                        onUnlock = {
                            locker.authenticate(
                                onSuccess = { scope.launch { snack.showSnackbar("Kilit açıldı") } },
                                onFail = { msg -> scope.launch { snack.showSnackbar(msg) } }
                            )
                        }
                    )
                }

                NavHost(navController = nav, startDestination = "keys") {
                    composable("keys") {
                        KeyListScreen(
                            onCreate = { nav.navigate("create") },
                            onSettings = { nav.navigate("settings") },
                            onEncrypt = { nav.navigate("crypto") }
                        )
                    }
                    composable("create") { CreateKeyScreen(onBack = { nav.popBackStack() }) }
                    composable("crypto") { CryptoScreen(onBack = { nav.popBackStack() }) }
                    composable("settings") { SettingsScreen(onBack = { nav.popBackStack() }) }
                }

                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.BottomCenter) {
                    SnackbarHost(snack)
                }
            }
        }
    }
}

@Composable
private fun LockScreen(onUnlock: () -> Unit) {
    Box(
        modifier = Modifier.fillMaxSize().background(kibeleGradient()),
        contentAlignment = Alignment.Center
    ) {
        ElevatedCard(Modifier.padding(24.dp)) {
            Column(Modifier.padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(Icons.Filled.Lock, contentDescription = null)
                Spacer(Modifier.height(8.dp))
                Text("Kibele Kilitli", style = MaterialTheme.typography.titleLarge)
                Text("Devam etmek için kimlik doğrulayın.", style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(16.dp))
                Button(onClick = onUnlock) { Text("Kilidi Aç") }
            }
        }
    }
}

// ---------- Key Listesi ----------
data class KeyItem(val name: String, val algo: String, val date: LocalDate)

@Composable
fun KeyListScreen(onCreate: () -> Unit, onSettings: () -> Unit, onEncrypt: () -> Unit) {
    val items = remember {
        listOf(
            KeyItem("Müşteri Bilgileri", "AES-256", LocalDate.of(2023, 3, 12)),
            KeyItem("Müjde Raporu", "RSA-4096", LocalDate.of(2023, 3, 12)),
            KeyItem("Proje Raporu", "RSA-4096", LocalDate.of(2023, 3, 12)),
            KeyItem("Mișk İviğoiçi", "AES-256", LocalDate.of(2023, 3, 12))
        )
    }
    var query by remember { mutableStateOf("") }

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text("Anahtar Listesi") },
                actions = { IconButton(onClick = onSettings) {
                    Icon(Icons.Filled.Settings, contentDescription = null)
                } }
            )
        },
        floatingActionButton = {
            Row(Modifier.padding(end = 8.dp)) {
                ExtendedFloatingActionButton(
                    onClick = onCreate,
                    icon = { Icon(imageVector = Icons.Filled.Add, contentDescription = null) },
                    text = { Text("Yeni Anahtar Ekle") }
                )
                Spacer(Modifier.width(12.dp))
                ExtendedFloatingActionButton(onClick = onEncrypt) { Text("Şifrele / Çöz") }
            }
        }
    ) { padding ->
        Column(
            Modifier.fillMaxSize().background(kibeleGradient())
                .padding(padding).padding(16.dp)
        ) {
            OutlinedTextField(
                value = query, onValueChange = { query = it },
                placeholder = { Text("Anahtar Ara…") }, singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(12.dp))
            LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                items(items.filter { it.name.contains(query, ignoreCase = true) }) { item ->
                    KeyRow(item)
                }
            }
        }
    }
}

@Composable
fun KeyRow(item: KeyItem) {
    ElevatedCard(Modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(item.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(item.algo, style = MaterialTheme.typography.bodySmall)
            }
            val d = item.date
            Text("${d.dayOfMonth.toString().padStart(2,'0')}.${d.monthValue.toString().padStart(2,'0')}.${d.year}",
                style = MaterialTheme.typography.labelMedium)
        }
    }
}

// ---------- Yeni Anahtar ----------
@Composable
fun CreateKeyScreen(onBack: () -> Unit) {
    var name by remember { mutableStateOf("kibele_rsa_v1") }
    var pass by remember { mutableStateOf("") }
    var pass2 by remember { mutableStateOf("") }
    var bits by remember { mutableStateOf(4096) }
    var algo by remember { mutableStateOf("RSA") }
    val scope = rememberCoroutineScope()
    val snack = remember { SnackbarHostState() }

    Scaffold(
        topBar = {
            SmallTopAppBar(title = { Text("Yeni Anahtar Oluştur") },
                navigationIcon = { TextButton(onClick = onBack) { Text("Geri") } })
        },
        snackbarHost = { SnackbarHost(snack) }
    ) { padding ->
        Column(
            Modifier.fillMaxSize().background(kibeleGradient())
                .padding(padding).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("Anahtar Adı (Alias)") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = pass, onValueChange = { pass = it }, label = { Text("Şifre (isteğe bağlı)") }, visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = pass2, onValueChange = { pass2 = it }, label = { Text("Şifreyi Tekrar Girin") }, visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())

            Text("Anahtar Uzunluğu", style = MaterialTheme.typography.labelLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SegButton("2048 bit", bits == 2048) { bits = 2048 }
                SegButton("3072 bit", bits == 3072) { bits = 3072 }
                SegButton("4096 bit", bits == 4096) { bits = 4096 }
            }

            Text("Algoritma", style = MaterialTheme.typography.labelLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SegButton("RSA", algo == "RSA") { algo = "RSA" }
                SegButton("AES-256", algo == "AES") { algo = "AES" }
            }

            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(onClick = {
                    try {
                        if (algo == "RSA") {
                            RsaHybrid.generateRsaIfMissing(name, bits)
                            scope.launch { snack.showSnackbar("RSA $bits oluşturuldu: $name") }
                        } else {
                            scope.launch { snack.showSnackbar("AES (Keystore) otomatik üretiliyor.") }
                        }
                    } catch (t: Throwable) {
                        scope.launch { snack.showSnackbar("Hata: ${t.message ?: "bilinmiyor"}") }
                    }
                }) { Text("Anahtar Oluştur") }
                OutlinedButton(onClick = onBack) { Text("İptal") }
            }
        }
    }
}

@Composable private fun SegButton(text: String, selected: Boolean, onClick: () -> Unit) {
    if (selected) FilledTonalButton(onClick = onClick) { Text(text) }
    else OutlinedButton(onClick = onClick) { Text(text) }
}

// ---------- AES-256-GCM (Keystore) ----------
private object AesLocal {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val AES_ALIAS = "kibele_aes_v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val IV_SIZE = 12

    private fun getOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getEntry(AES_ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            AES_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        gen.init(spec)
        return gen.generateKey()
    }

    fun encrypt(plain: ByteArray): String {
        val c = Cipher.getInstance(TRANSFORMATION)
        c.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val iv = c.iv
        val out = c.doFinal(plain)
        val bb = ByteBuffer.allocate(2 + IV_SIZE + out.size)
        bb.put('v'.code.toByte()); bb.put('1'.code.toByte()); bb.put(iv); bb.put(out)
        return Base64.encodeToString(bb.array(), Base64.NO_WRAP)
    }

    fun decrypt(b64: String): ByteArray {
        val all = Base64.decode(b64, Base64.NO_WRAP)
        require(all.size > 14) { "Geçersiz veri" }
        require(all[0].toInt().toChar() == 'v' && all[1].toInt().toChar() == '1') { "Sürüm desteklenmiyor" }
        val iv = all.copyOfRange(2, 14)
        val cipherText = all.copyOfRange(14, all.size)
        val c = Cipher.getInstance(TRANSFORMATION)
        c.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))
        return c.doFinal(cipherText)
    }
}

// ---------- RSA-4096 Hibrit (RSA-OAEP + AES-GCM) ----------
private object RsaHybrid {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    private const val AES_TRANSFORMATION = "AES/GCM/NoPadding"
    private const val IV_SIZE = 12

    fun generateRsaIfMissing(alias: String, keySize: Int = 4096) {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (ks.containsAlias(alias)) return
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setKeySize(keySize)
            .build()
        kpg.initialize(spec); kpg.generateKeyPair()
    }

    fun encrypt(plain: ByteArray, alias: String): String {
        generateRsaIfMissing(alias)
        val aesKeyBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val aesKey = SecretKeySpec(aesKeyBytes, "AES")
        val aes = Cipher.getInstance(AES_TRANSFORMATION)
        aes.init(Cipher.ENCRYPT_MODE, aesKey)
        val iv = aes.iv
        val enc = aes.doFinal(plain)

        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val pubKey = ks.getCertificate(alias).publicKey
        val rsa = Cipher.getInstance(RSA_TRANSFORMATION)
        rsa.init(Cipher.ENCRYPT_MODE, pubKey)
        val wrapped = rsa.doFinal(aesKeyBytes)

        val bb = ByteBuffer.allocate(2 + 2 + wrapped.size + IV_SIZE + enc.size)
        bb.put('h'.code.toByte()); bb.put('1'.code.toByte())
        bb.putShort(wrapped.size.toShort())
        bb.put(wrapped); bb.put(iv); bb.put(enc)
        return Base64.encodeToString(bb.array(), Base64.NO_WRAP)
    }

    fun decrypt(b64: String, alias: String): ByteArray {
        val data = Base64.decode(b64, Base64.NO_WRAP)
        require(data.size > 4 + IV_SIZE) { "Geçersiz veri" }
        require(data[0].toInt().toChar() == 'h' && data[1].toInt().toChar() == '1') { "Sürüm desteklenmiyor" }
        var off = 2
        val keyLen = ((data[off].toInt() and 0xFF) shl 8) or (data[off + 1].toInt() and 0xFF); off += 2
        val wrapped = data.copyOfRange(off, off + keyLen); off += keyLen
        val iv = data.copyOfRange(off, off + IV_SIZE); off += IV_SIZE
        val cipherText = data.copyOfRange(off, data.size)

        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val priv = ks.getKey(alias, null) ?: error("RSA anahtarı yok: $alias")
        val rsa = Cipher.getInstance(RSA_TRANSFORMATION)
        rsa.init(Cipher.DECRYPT_MODE, priv)
        val aesKeyBytes = rsa.doFinal(wrapped)

        val aes = Cipher.getInstance(AES_TRANSFORMATION)
        aes.init(Cipher.DECRYPT_MODE, SecretKeySpec(aesKeyBytes, "AES"), GCMParameterSpec(128, iv))
        return aes.doFinal(cipherText)
    }
}

// ---------- Şifrele / Şifre Çöz ----------
private enum class CryptoMode { AES_LOCAL, RSA_HYBRID }

@Composable
fun CryptoScreen(onBack: () -> Unit) {
    var plain by remember { mutableStateOf("") }
    var cipherText by remember { mutableStateOf("") }
    var mode by remember { mutableStateOf(CryptoMode.AES_LOCAL) }
    var rsaAlias by remember { mutableStateOf("kibele_rsa_v1") }

    val snackbarHost = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current

    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = { Text("Şifrele / Şifre Çöz") },
                navigationIcon = { TextButton(onClick = onBack) { Text("Geri") } }
            )
        },
        snackbarHost = { SnackbarHost(hostState = snackbarHost) }
    ) { padding ->
        Column(
            Modifier.fillMaxSize().background(kibeleGradient())
                .padding(padding).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text("Mod", style = MaterialTheme.typography.labelLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SegButton("AES-256 (Yerel)", mode == CryptoMode.AES_LOCAL) { mode = CryptoMode.AES_LOCAL }
                SegButton("RSA Hibrit", mode == CryptoMode.RSA_HYBRID) { mode = CryptoMode.RSA_HYBRID }
            }
            if (mode == CryptoMode.RSA_HYBRID) {
                OutlinedTextField(
                    value = rsaAlias, onValueChange = { rsaAlias = it },
                    label = { Text("RSA Alias") }, singleLine = true, modifier = Modifier.fillMaxWidth()
                )
            }

            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {

                ElevatedCard(Modifier.weight(1f)) {
                    Column(Modifier.padding(12.dp)) {
                        Text("Metin")
                        OutlinedTextField(
                            value = plain, onValueChange = { plain = it },
                            placeholder = { Text("Metin") },
                            modifier = Modifier.fillMaxWidth().height(160.dp)
                        )
                        Spacer(Modifier.height(8.dp))
                        Button(onClick = {
                            try {
                                cipherText = when (mode) {
                                    CryptoMode.AES_LOCAL -> AesLocal.encrypt(plain.encodeToByteArray())
                                    CryptoMode.RSA_HYBRID -> RsaHybrid.encrypt(plain.encodeToByteArray(), rsaAlias)
                                }
                                scope.launch { snackbarHost.showSnackbar("Şifrelendi") }
                            } catch (t: Throwable) {
                                scope.launch { snackbarHost.showSnackbar("Şifreleme hatası: ${t.message ?: "bilinmiyor"}") }
                            }
                        }) { Text("Şifrele") }
                    }
                }

                ElevatedCard(Modifier.weight(1f)) {
                    Column(Modifier.padding(12.dp)) {
                        Text("Giriş")
                        OutlinedTextField(
                            value = cipherText, onValueChange = { cipherText = it },
                            placeholder = { Text(if (mode==CryptoMode.AES_LOCAL) "Giriş (v1 Base64)" else "Giriş (h1 Base64)") },
                            modifier = Modifier.fillMaxWidth().height(160.dp)
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 8.dp)) {
                            OutlinedButton(onClick = {
                                clipboard.setText(AnnotatedString(cipherText))
                                scope.launch {
                                    snackbarHost.showSnackbar("Panoya kopyalandı (30 sn sonra temizlenecek)")
                                    delay(30_000)
                                    clipboard.setText(AnnotatedString(""))
                                    snackbarHost.showSnackbar("Pano temizlendi")
                                }
                            }) { Text("Kopyala") }
                            OutlinedButton(onClick = { cipherText = "" }) { Text("Temizle") }
                        }

                        Spacer(Modifier.height(8.dp))
                        Button(onClick = {
                            try {
                                val dec = when (mode) {
                                    CryptoMode.AES_LOCAL -> AesLocal.decrypt(cipherText)
                                    CryptoMode.RSA_HYBRID -> RsaHybrid.decrypt(cipherText, rsaAlias)
                                }
                                plain = dec.decodeToString()
                                scope.launch { snackbarHost.showSnackbar("Çözüldü") }
                            } catch (t: Throwable) {
                                scope.launch { snackbarHost.showSnackbar("Çözme hatası: ${t.message ?: "geçersiz veri"}") }
                            }
                        }) { Text("Şifre Çöz") }
                    }
                }
            }
        }
    }
}

// ---------- Ayarlar ----------
@Composable
fun SettingsScreen(onBack: () -> Unit) {
    var notif by remember { mutableStateOf(true) }
    var appLock by remember { mutableStateOf(true) }
    var lang by remember { mutableStateOf(true) }
    var protocols by remember { mutableStateOf(true) }

    Scaffold(topBar = {
        SmallTopAppBar(title = { Text("Ayarlar") },
            navigationIcon = { TextButton(onClick = onBack) { Text("Geri") } })
    }) { padding ->
        Column(
            Modifier.fillMaxSize().background(kibeleGradient())
                .padding(padding).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            SettingRow("Hesap Bilgileri")
            SettingRow("Şifre Değiştir")
            SwitchRow("Bildirimler", notif) { notif = it }
            SettingRow("Veri Şifreleme Ayarları")
            SwitchRow("Uygulama Kilidi", appLock) { appLock = it }
            SwitchRow("Dil Seçimi", lang) { lang = it }
            SwitchRow("Güvenlik Protokolleri", protocols) { protocols = it }
            SettingRow("Yardım")
            SettingRow("Hakkında")
        }
    }
}

@Composable private fun SettingRow(title: String) {
    ElevatedCard(Modifier.fillMaxWidth()) { Text(title, Modifier.padding(16.dp)) }
}
@Composable private fun SwitchRow(title: String, checked: Boolean, onChecked: (Boolean)->Unit) {
    ElevatedCard(Modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(title, Modifier.weight(1f))
            Switch(checked = checked, onCheckedChange = onChecked)
        }
    }
}
