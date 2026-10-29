# Android Application Security — Study Guide

This guide continues from your foundation notes (Android internals, APK structure,
ART/Dalvik, the sandbox, the manifest and components, signing, static analysis,
SSL pinning bypass, Frida/objection, root-detection bypass, Flutter bypass).

It teaches the **attacks those notes did not cover**. For each attack you get:
1. **What it is** — a plain explanation of the weakness.
2. **Why it matters** — what an attacker gains.
3. **Techniques** — how to test for it, each step explained.

Language is kept simple and direct, with no unrelated analogies.

---

## How to use this guide

Work top to bottom the first time — the order moves from on-device data, to the
app's exposed entry points, to the network and backend. Once you know the material,
use the checklist at the end as your methodology.

Prerequisite skills (from your notes): decompiling with jadx/apktool, reading the
manifest, using adb and a rooted emulator, running Frida and objection.

---

# PART A — Data stored on the device

## A1. Insecure Data Storage

**What it is.**
The app saves information on the phone that should be protected — for example a
password, a session token, an API key, or personal data — but saves it in a form
that can be read by anyone who gets access to the file. "Protected" means encrypted
with a key held in secure hardware. "Readable" means plain text, or something trivial
like Base64 that only looks encoded.

**Why it matters.**
If an attacker has the phone (stolen, lost, or malware with file access) or a backup
of it, they can read these files and get accounts, tokens, or private data without
needing the password.

**Where apps store data (all under `/data/data/<package-name>/`):**
- `shared_prefs/` — small key/value settings saved as XML files.
- `databases/` — SQLite database files.
- `files/` — any files the app writes itself.
- `cache/` — temporary files (web content, images, API responses).
- External storage (`/sdcard/...`) — storage that, on older Android, other apps can read.

**Techniques.**

1. **Open a shell and go to the app's data directory.**
   ```
   adb -s emulator-5556 shell
   run-as <package>      # works if the app is debuggable; otherwise become root
   cd /data/data/<package>
   ls -la
   ```
   `run-as` lets you act as the app's own user so you can read its private files.

2. **Read the shared preferences.**
   ```
   cat shared_prefs/*.xml
   ```
   Look for keys named like `password`, `token`, `auth`, `pin`, `apikey`, `session`.
   A value stored here in plain text is a finding.

3. **Open the databases.**
   ```
   sqlite3 databases/<name>.db
   .tables
   SELECT * FROM <table>;
   ```
   Look for stored credentials, tokens, cached messages, or personal data.

4. **Inspect files and cache.**
   ```
   ls -la files/ cache/
   cat files/<file>
   strings files/<file>
   ```
   `strings` shows readable text inside binary files.

5. **Check external storage.**
   Look under `/sdcard/Android/data/<package>/` and any folder the app writes to.
   Anything sensitive here is worse, because it is easier for other apps to read.

6. **Judge the finding.**
   Sensitive data should live in the **Android Keystore** or in
   **EncryptedSharedPreferences**, not in plain prefs/DB/files. If you can read it
   with `cat` or `sqlite3`, report it. The fix is to encrypt it with a key stored in
   the Keystore.

---

## A2. Insecure Logging

**What it is.**
The app prints sensitive information to the system log while it runs. Logs are meant
for debugging, but if they contain passwords, tokens, card numbers, or personal data,
anything that can read the log can steal them.

**Why it matters.**
On older Android other apps could read logs. On a device the tester or malware
controls, logs are easy to read. Developers often forget to remove debug logging
before release.

**Techniques.**

1. **Watch the log while using the app.**
   ```
   adb logcat
   ```
   Then open the app and move through each screen — login, payment, profile.

2. **Filter the noise.**
   ```
   adb logcat | grep -iE "password|token|pin|card|otp|secret|auth"
   ```
   This shows only lines that may contain secrets.

3. **Record the exact action that caused the leak** (which screen, which button), so
   the report has a clear reproduction step.

A finding is any sensitive value appearing in the log. The fix is to remove or mask
that logging in release builds.

---

## A3. Insecure Backup / Data Extraction

**What it is.**
Android has a backup feature. If the app allows backup, its private data can be
copied off the device using `adb` — **without root** — and then read on your computer.

**Why it matters.**
It means an attacker with brief physical access (and USB debugging) can extract the
app's private data, bypassing the normal file permissions.

**How to know it applies.**
In the manifest, `android:allowBackup="true"` (this is the default when not set).

**Techniques.**

1. **Take a backup of the app.**
   ```
   adb backup -f backup.ab -noapk <package>
   ```
   Confirm on the device screen. This produces an `backup.ab` file.

2. **Convert the backup to a normal archive.**
   The `.ab` file has a 24-byte header then zlib-compressed data. Use the
   Android Backup Extractor tool (`abe.jar`):
   ```
   java -jar abe.jar unpack backup.ab backup.tar
   tar xvf backup.tar
   ```

3. **Read the extracted files** — shared_prefs, databases, files — exactly as in A1.
   Any sensitive data recovered this way is the finding. The fix is to set
   `allowBackup="false"` or exclude sensitive files from backup.

---

# PART B — The app's exposed entry points (IPC)

Background: Android apps are split into **components** — activities (screens),
services (background tasks), broadcast receivers (event listeners), and content
providers (data sharing). A component with `android:exported="true"` can be started
or accessed by **other apps**, not just its own. Each exported component is therefore
a way into the app that skips the normal user flow. The attacks below abuse that.

## B1. Exported Activity Exploitation

**What it is.**
An activity is one screen. If it is exported, another app (or you, with adb) can open
that screen directly. If the app assumed a screen could only be reached after login,
opening it directly can skip the login.

**Why it matters.**
You may reach protected screens (account details, admin panels), make the app perform
actions, or feed the screen crafted input through "intent extras" (data passed when
starting a screen).

**Techniques.**

1. **Find exported activities** in the manifest: `android:exported="true"` on
   `<activity>`, or an activity with an `<intent-filter>` (which makes it exported by
   default on older targetSdk).

2. **Open an exported activity directly.**
   ```
   adb shell am start -n <package>/<activity-name>
   ```
   `am start` asks Android to open that specific screen. If a login screen is skipped,
   that is a broken-access-control finding.

3. **Pass crafted extras to influence logic.**
   ```
   am start -n <package>/.AdminActivity --es "role" "admin" --ez "isLoggedIn" true --ei "userId" 1
   ```
   `--es` passes a string, `--ez` a true/false, `--ei` a number. If the screen trusts
   these values (for example treats `isLoggedIn true` as logged in), you have bypassed
   a control.

4. **Record what the screen reveals or does.** Sensitive data shown, or an action
   performed, is the finding. The fix is to not export the activity, or to re-check
   authentication and never trust intent extras for access decisions.

---

## B2. Exported Broadcast Receiver Exploitation

**What it is.**
A broadcast receiver listens for messages ("broadcasts") — system events like "battery
low", or custom app events like "payment completed". If a receiver is exported, any app
can send it that message and trigger whatever the receiver does.

**Why it matters.**
If the receiver performs a sensitive action when it gets a message (unlocks a feature,
marks a payment complete, changes a setting), you can trigger it yourself by sending a
fake broadcast.

**Techniques.**

1. **Find exported receivers** in the manifest (`<receiver android:exported="true">`
   or with an `<intent-filter>`), and note the action name it listens for.

2. **Send a crafted broadcast.**
   ```
   adb shell am broadcast -a <action-name> --es "key" "value" -n <package>/<receiver-name>
   ```
   `-a` sets the action it listens for; extras pass data the receiver reads.

3. **Observe the effect.** If sending the broadcast causes a privileged action, that is
   the finding. The fix is to not export the receiver, or require a permission to send
   to it.

---

## B3. Exported Service Exploitation

**What it is.**
A service runs tasks in the background with no screen. If exported, another app can
start or bind to it and make it run its tasks.

**Why it matters.**
Exported services can expose functionality that was meant to be internal — for example
a service that processes commands, handles data, or performs actions on behalf of the app.

**Techniques.**

1. **Find exported services** in the manifest (`<service android:exported="true">`).

2. **Start the service with input.**
   ```
   adb shell am startservice -n <package>/<service-name> --es "cmd" "value"
   ```

3. **See what it does** with the input you passed. If it performs something sensitive
   based on your input, that is the finding. The fix is to not export it, or protect it
   with a permission and validate input.

---

## B4. Content Provider Exploitation

**What it is.**
A content provider is the component that shares data between apps through a URL that
starts with `content://`. If it is exported or misconfigured, other apps can read or
write its data. Two specific bugs appear here: **SQL injection** and **path traversal**.

**Why it matters.**
- Reading the provider may expose data the app did not intend to share.
- **SQL injection**: many providers build a database query using text you supply. If
  they do not do it safely, you can change the query to return all rows or read other
  tables.
- **Path traversal**: some providers return files. If they build the file path from
  your input without checking it, you can ask for files outside the intended folder,
  such as the app's private files.

**Techniques.**

1. **Find the provider's address.** In the manifest, `<provider>` has an
   `android:authorities` value. The base URL is `content://<authority>/`.

2. **Query the provider.**
   ```
   adb shell content query --uri content://<authority>/<path>
   ```
   If it returns data without any permission, that is already a disclosure issue.

3. **Test for SQL injection** in the part of the query you control (the "selection").
   ```
   adb shell content query --uri content://<authority>/users --where "1=1"
   adb shell content query --uri content://<authority>/users --where "1=1) UNION SELECT name,sql FROM sqlite_master--"
   ```
   If `1=1` returns all rows, or the UNION query returns database structure, the
   provider is injectable.

4. **Test for path traversal** on providers that serve files. Ask for a path that
   climbs out of the intended folder:
   ```
   adb shell content read --uri content://<authority>/../../../../data/data/<package>/shared_prefs/prefs.xml
   ```
   If you get a file you should not be able to read, that is the finding.

5. **drozer** automates all of the above:
   ```
   run app.provider.info -a <package>
   run scanner.provider.injection -a <package>
   run scanner.provider.traversal -a <package>
   ```
   Learning drozer here is worth it — it tests every provider quickly.

The fixes: do not export providers that do not need sharing; use parameterised queries
(not string-built SQL); and validate/normalise any file path before serving it.

---

## B5. Deep Link and Intent Attacks

**What it is.**
A deep link is a special URL that opens the app at a certain screen, for example
`myapp://account/details?id=5`. The app registers these links in the manifest. The
problem is that a deep link can be sent to the app by **any** source — another app, a
web page, a QR code — and the data inside it (`id=5`) may be trusted by the app when it
should not be.

**Why it matters.**
Three common problems:
- **Parameter injection**: the value in the link reaches a database query, a file path,
  or an access decision.
- **Open redirect / WebView load**: the link contains a URL that the app loads in a
  WebView, so an attacker can make the app show their page.
- **Intent redirection**: the app takes an intent (or part of one) from the link and
  passes it to an internal component, letting an attacker reach components they could
  not reach directly.

**Techniques.**

1. **Find the deep links** in the manifest: `<intent-filter>` with a `<data>` tag that
   has `android:scheme`, `android:host`, `android:pathPattern`.

2. **Trigger a deep link with adb.**
   ```
   adb shell am start -a android.intent.action.VIEW -d "myapp://account/details?id=5" <package>
   ```
   `-d` is the link. Change the parameters and watch what the app does.

3. **Test the parameters** the same way you test any input: put a different `id` to see
   other users' data (access control), put SQL or path characters to see if they reach
   a query or file, put a URL to see if it is loaded in a WebView.

4. **Test for WebView redirect**: if a link parameter ends up as the URL in a WebView,
   point it at a page you control and confirm the app loads it.

The fix is to validate every value from a deep link and never use it for access
decisions or to build queries/paths/URLs without checking.

---

# PART C — WebViews

## C1. WebView Attacks

**What it is.**
A WebView is a browser window embedded inside the app, used to show web pages. WebViews
have settings that, if turned on carelessly, let web content do dangerous things —
call into the app's Java code, or read local files.

**Why it matters.**
If an attacker can control the page shown in a WebView (through a deep link, a link in
the app, or by intercepting network traffic), these weaknesses can turn a web page into
code running in the app, or into theft of the app's private files.

**The specific weaknesses and how to test them.**

1. **JavaScript bridge (`addJavascriptInterface`).**
   This setting exposes a Java object to the JavaScript in the page, so the page can
   call app methods. On old target versions (below API 17) this gave full code
   execution. Even now, if the exposed object has risky methods, the page can call them.
   - **How to test:** in the decompiled code, search for `addJavascriptInterface` and
     look at the exposed class and its `@JavascriptInterface` methods. If you can make
     the WebView load your page, call those methods from your JavaScript and see what
     they do.

2. **File access (`setAllowFileAccess`, `setAllowUniversalAccessFromFileURLs`).**
   If on, a page can open `file://` URLs and read the app's local files.
   - **How to test:** search the code for these settings. If enabled, load a page that
     reads `file:///data/data/<package>/shared_prefs/...` and see if it returns the
     contents.

3. **JavaScript enabled with untrusted content (`setJavaScriptEnabled(true)`).**
   If the WebView loads content you can influence and runs JavaScript, you may get XSS
   inside the app, and with a bridge, native calls.
   - **How to test:** find where the WebView's URL or HTML comes from. If any of it
     comes from input you control, inject a script and confirm it runs.

4. **Ignoring certificate errors (`onReceivedSslError` calling `handler.proceed()`).**
   This makes the WebView accept invalid certificates, allowing a man-in-the-middle to
   feed it a malicious page.
   - **How to test:** search for `onReceivedSslError`. If it proceeds on error, note it;
     it enables the attacks above over the network.

The fixes: do not add JavaScript bridges unless required (and keep exposed methods
safe), disable file access, only load trusted URLs, and never ignore SSL errors.

---

# PART D — Network and cryptography

## D1. Insecure Communication (beyond SSL pinning)

**What it is.**
Your notes cover **SSL pinning** (the app only accepting one specific certificate) and
how to bypass it to intercept traffic. There are other network weaknesses to check once
you can see the traffic.

**The weaknesses and how to test them.**

1. **Cleartext (HTTP) traffic.**
   Data sent over plain HTTP can be read and changed on the network.
   - **How to test:** in the manifest look for `android:usesCleartextTraffic="true"`, and
     in `res/xml/network_security_config.xml` look for `cleartextTrafficPermitted="true"`.
     Then intercept and confirm any endpoint uses `http://`.

2. **Accept-all certificate validation (in code).**
   Some apps replace the normal certificate check with one that accepts everything. This
   breaks TLS even without pinning.
   - **How to test:** in the decompiled code, search for `X509TrustManager`,
     `checkServerTrusted` (an empty body accepts all), and `HostnameVerifier` that always
     returns true. These mean a man-in-the-middle works easily.

3. **Weak network security config.**
   The config file can trust user-added certificates or leave debug overrides in the
   release build, both of which make interception easier.
   - **How to test:** read `network_security_config.xml` and note any `trust-anchors`
     adding user certificates or any `debug-overrides`.

The fix is HTTPS everywhere, correct certificate and hostname validation, and a strict
network security config.

---

## D2. Insecure Cryptography

**What it is.**
The app uses encryption or hashing, but does it in a way that can be broken — a weak
algorithm, a key written into the app, a predictable value where a random one is needed,
or encryption that is really just encoding.

**Why it matters.**
Weak cryptography means data the app thought was protected can be recovered or forged.

**The weaknesses and how to test them.**

1. **Hardcoded keys.**
   A key written into the source code or resources is available to anyone who decompiles
   the app.
   - **How to test:** search the decompiled code and `strings.xml` for key material — long
     Base64/hex strings near `SecretKeySpec`, `IvParameterSpec`, `Cipher`.

2. **Weak algorithms.**
   `DES`, `RC4`, `MD5`, and `SHA1` are outdated. **ECB mode** (seen as `AES/ECB/...`) leaks
   patterns in the data.
   - **How to test:** search the code for these algorithm names and cipher strings.

3. **Static or reused IV/nonce.**
   An IV (initialisation value) must be random for each encryption. A fixed IV weakens
   the encryption.
   - **How to test:** look at how `IvParameterSpec` is built — a constant value is a bug.

4. **Insecure randomness.**
   Tokens, IVs, and keys must come from `SecureRandom`. `java.util.Random` or
   `Math.random()` are predictable.
   - **How to test:** search for `Random(` and `Math.random` in security-related code.

5. **Keys not kept in the Keystore.**
   Keys stored in prefs or files instead of the Android Keystore can be stolen (see A1).

**Confirming at runtime.** With Frida you can hook the cipher setup and print the key,
IV, and plaintext as the app runs, which proves the weakness.

---

# PART E — Authentication controls on the device

## E1. Client-Side Authentication Bypass

**What it is.**
The app checks a PIN, password, or other secret **on the device itself** instead of on
the server. Because the check runs on a device you control, you can read the expected
value or force the check to pass.

**Why it matters.**
Any security decision made only on the client can be bypassed, because the attacker owns
the client.

**Techniques.**

1. **Find the check in the code.** Look for where user input is compared to a value —
   an `if` comparing the entered PIN to a string, a stored hash, or a value returned by a
   method. (Your notes' "hardcoded string comparison" examples are exactly this.)

2. **Recover the expected value (static).** If the value is a hardcoded string, an
   obfuscated string, or a Base64 value in another class, decode it and use it directly.

3. **Force the check to pass (dynamic, with Frida).** Hook the method that returns the
   result and make it always return "correct":
   ```javascript
   Java.perform(function () {
     var C = Java.use("com.app.PinManager");
     C.verifyPin.implementation = function (entered) {
       return true;   // always report the PIN as correct
     };
   });
   ```

A bypass here is the finding. The fix is to perform real authentication on the server.

---

## E2. Biometric Authentication Bypass

**What it is.**
The app uses fingerprint/face unlock. There are two ways apps do this. The weak way only
asks the system "did biometric succeed?" and then shows the protected content — the result
is a simple success/failure the attacker can fake. The strong way ties the biometric to
unlocking a key in the Keystore, so faking the result gives nothing because the key stays
locked.

**Why it matters.**
If the app uses the weak way, you can skip the fingerprint entirely.

**Techniques.**

1. **Check which way the app uses biometrics.** In the code, if biometric success simply
   calls a method that reveals data or navigates forward (and no Keystore key is used),
   it is the weak way.

2. **Call the success path directly with Frida.** Hook the success callback so the app
   behaves as if biometric passed:
   ```javascript
   Java.perform(function () {
     var cb = Java.use("androidx.biometric.BiometricPrompt$AuthenticationCallback");
     cb.onAuthenticationSucceeded.implementation = function (result) {
       // call original with a crafted/empty result, or trigger the app's next step
       return this.onAuthenticationSucceeded(result);
     };
   });
   ```
   If this unlocks the app, biometric was only a UI gate.

3. **If a Keystore key is used**, this will not work — note that the app implemented it
   correctly. The fix for the weak case is to bind biometric to a Keystore key.

---

# PART F — Runtime, memory, and UI leakage

## F1. Runtime Manipulation with Frida (general)

**What it is.**
Frida lets you read and change the app while it runs. Your notes use it for SSL and root
bypass; the general skill is hooking any method to inspect inputs/outputs or change
behaviour. This is how you bypass client-side logic, read secrets in memory, and prove
findings.

**Core techniques.**

1. **Log a method's inputs and output** (to understand or find secrets):
   ```javascript
   Java.perform(function () {
     var C = Java.use("com.app.Crypto");
     C.decrypt.implementation = function (data) {
       var out = this.decrypt(data);
       console.log("[decrypt] in=" + data + " out=" + out);
       return out;
     };
   });
   ```
2. **Change a return value** to bypass a check (as in E1/E2).
3. **Call a method directly** to decrypt a value or reach hidden functionality.
4. **objection shortcuts** (from your notes): `android hooking list classes`,
   `android hooking search methods <keyword>`, `memory dump all`, `sqlite connect`,
   `android keystore list`, `android clipboard monitor`.

## F2. Memory and Runtime Data Exposure

**What it is.**
Secrets that are safe on disk may still sit in the app's memory in plain text while it
runs. If an attacker can dump memory, they can recover them.

**Techniques.**
```
objection -g <package> explore
memory dump all ./memdump
strings ./memdump/* | grep -iE "password|token|card|pin"
```
Finding secrets in the dump shows they are not cleared from memory after use.

## F3. Clipboard, Screenshot, and UI Leakage

**What it is.**
Sensitive data can leak through the device's shared features — the clipboard (shared
between apps), screenshots and the app-switcher preview (which can capture a screen with
secrets), and auto-filled fields.

**Techniques.**
1. **Clipboard:** `android clipboard monitor` in objection while you copy a card number
   or password in the app; if it appears, the app allowed copying sensitive data.
2. **Screenshot / app-switcher:** open a sensitive screen, then the app switcher. If the
   preview shows the sensitive data, the app did not hide its screen (fixed with
   `FLAG_SECURE`).
3. **Keyboard cache:** sensitive fields should disable suggestions/caching; check the
   input type on password/card fields.

## F4. Tapjacking / Overlay Attacks

**What it is.**
Another app draws an invisible layer on top of this app, so when the user thinks they are
tapping this app, they are really tapping the attacker's hidden buttons — or the attacker
reads what is underneath.

**Why it matters.**
A sensitive action (confirm payment, grant permission) can be tricked out of the user.

**How to test.**
Check whether sensitive buttons set `android:filterTouchesWhenObscured="true"` (which
blocks touches when something is drawn over them). If not, the screen can be overlaid.

---

# PART G — The backend (where the biggest bugs are)

## G1. Backend / API Attacks

**What it is.**
The app talks to a server through an API. The app itself is only the client; the server
is where accounts, money, and data actually live. Many of the most serious bugs are in
the API, which trusts the app too much.

**Why it matters.**
Once you can see and replay the app's API requests (after bypassing pinning), you can
test the server directly, and server weaknesses affect every user, not just the phone in
your hand.

**Techniques.**
1. **Capture the traffic.** Bypass SSL pinning (your notes) and proxy the app through
   Burp Suite so you see every request and response.
2. **Broken access control / IDOR.** Change an ID in a request (`userId=5` to `userId=6`)
   and see if you get another user's data or actions.
3. **Authentication and session.** Test token handling — does it expire, can it be
   reused, is it validated properly (for JWTs, check the signature and claims).
4. **Injection.** Test API parameters for SQL, NoSQL, and command injection, the same way
   as a web application.
5. **Excessive data exposure.** Compare what the API returns to what the app shows — the
   API often returns extra fields (other users' data, internal flags).
6. **Business logic.** Replay or reorder requests to skip steps (for example confirm an
   order without paying).

Test the API as thoroughly as a web app — this is usually where criticals are found.

---

# PART H — Resilience (defences and their bypass)

Your notes already cover root-detection bypass, emulator spoofing (`spoofbuild.js`), and
SSL pinning bypass. For completeness, resilience features are: root detection, emulator
detection, debugger/Frida detection, tamper/signature checks, and code obfuscation. For a
test, your job is to **document which are present and whether you could bypass them**.
They are defence-in-depth — they slow an attacker down but do not fix the real
vulnerabilities, so never let their presence stop you from testing the items above.

---

# Methodology checklist (build your own from this)

**On-device data**
- [ ] shared_prefs read for secrets (A1)
- [ ] SQLite databases dumped (A1)
- [ ] files/ and cache/ inspected (A1)
- [ ] external storage checked (A1)
- [ ] logcat reviewed per screen (A2)
- [ ] backup extracted if allowBackup (A3)

**Exposed components (IPC)**
- [ ] exported activities opened + extras tested (B1)
- [ ] exported receivers triggered (B2)
- [ ] exported services started (B3)
- [ ] content providers: query, SQLi, path traversal (B4)
- [ ] deep links enumerated + parameters tested (B5)

**WebView**
- [ ] addJavascriptInterface reviewed (C1)
- [ ] file access settings reviewed (C1)
- [ ] untrusted content / XSS (C1)
- [ ] SSL error handling (C1)

**Network & crypto**
- [ ] cleartext traffic (D1)
- [ ] certificate/hostname validation in code (D1)
- [ ] network_security_config reviewed (D1)
- [ ] hardcoded keys / weak algos / static IV / weak random (D2)

**Auth on device**
- [ ] client-side auth bypass (E1)
- [ ] biometric bypass (E2)

**Runtime & UI**
- [ ] memory dump for secrets (F2)
- [ ] clipboard / screenshot / keyboard leakage (F3)
- [ ] tapjacking (F4)

**Backend**
- [ ] IDOR / access control (G1)
- [ ] auth / session (G1)
- [ ] injection (G1)
- [ ] excessive data exposure (G1)
- [ ] business logic (G1)

**Resilience**
- [ ] root / emulator / Frida / tamper detection documented + bypass notes (H)

---

## References
- OWASP MASTG / MASVS — https://mas.owasp.org/
- drozer — https://github.com/WithSecureLabs/drozer
- Frida — https://frida.re/  · objection — https://github.com/sensepost/objection
- Android Backup Extractor (abe.jar) — for A3
