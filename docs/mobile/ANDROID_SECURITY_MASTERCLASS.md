# Android Application Security — Masterclass (from zero)

This is a complete, from-scratch study book for Android app penetration testing.
It assumes no prior knowledge. Every term is explained the first time it appears,
with real examples (real command output, real files, real code). It is written to be
read top to bottom.

Structure:
- **Chapters 1–9: Foundations** — what Android is and how it works, deeply.
- **Chapters 10–13: The testing process** — environment, getting the app, decompiling,
  static analysis.
- **Chapters 14–32: The attacks** — each one: *what it is → why it is vulnerable →
  techniques (with commands and examples)*.
- **Chapter 33: Methodology checklist.**

---

# CHAPTER 1 — What is Android?

Android is an **operating system (OS)** for phones, tablets, TVs, and watches. An
operating system is the software that sits between the physical device (the "hardware":
screen, memory, camera, radio) and the apps you use. The OS manages the hardware and
gives apps a safe, shared way to use it, so that app developers do not have to write code
for every different phone model.

Android was built by Google on top of an existing operating-system core called **Linux**.
So when we say "Android," we really mean: **the Linux core, plus a large stack of Google's
software on top of it, plus the apps.**

Two facts from this shape everything in security:

1. **Because Android is Linux underneath, it uses Linux's security features** — users,
   file permissions, and process isolation. Android reuses these to keep apps apart.
2. **Because apps are distributed as compiled packages that can be taken apart**, we (as
   testers) can decompile an app and read how it works, including mistakes the developer
   made.

The rest of the foundations explains both of these in detail.

---

# CHAPTER 2 — Android is a Linux system

## 2.1 What "Linux" means here

**Linux** is the **kernel** — the central part of an operating system. The kernel is the
program that is always running in the background and controls everything: it decides which
program gets to use the processor, manages memory, and talks to the hardware. Every other
program must go through the kernel to do anything real (read a file, use the network, draw
on the screen).

You can see that Android really is Linux. Connect to a device or emulator and ask:

```
$ adb shell
emulator:/ $ uname -a
Linux localhost 5.10.66 #1 SMP PREEMPT ... aarch64
```

`uname -a` prints the kernel name and version. It says **Linux**. The commands you can run
in this shell (`ls`, `cd`, `cat`, `ps`, `id`, `chmod`) are the same Linux commands used on
servers and desktops, because it is the same kernel.

## 2.2 Processes

A **process** is a running program. When you open an app, the system starts a process for
it. The kernel keeps a list of all processes and shares the processor between them.

```
emulator:/ $ ps -A | head
USER   PID  PPID  ...  NAME
root     1     0  ...  init
root   354     1  ...  zygote64
u0_a188 4120 354 ...  com.example.app
```

- `PID` is the process ID (a unique number).
- `PPID` is the parent process ID (which process started it).
- `USER` is which user the process runs as (Chapter 3).
- `init` (PID 1) is the first process started when the device boots; everything descends
  from it. `zygote64` is the process that launches apps (Chapter 8).

## 2.3 User mode and kernel mode

The processor can run code in two modes:
- **Kernel mode** — full, unrestricted access to all memory and hardware. Only the kernel
  runs here. A mistake in kernel mode can crash the whole device.
- **User mode** — restricted. Apps run here. They can only touch their own memory and must
  ask the kernel to do anything privileged.

The separation exists so that a buggy or malicious app cannot directly damage the system or
read other apps' memory.

## 2.4 System calls

When an app needs something only the kernel can do — read a file, open a network
connection, allocate memory — it makes a **system call** (often shortened to "syscall").
This is a request to the kernel to perform a privileged action on the app's behalf. The
kernel checks whether the app is allowed to do it, then does it and returns the result.

Example in plain terms: an app wants to read `/data/data/com.example.app/files/notes.txt`.
It does not touch the disk directly. It makes an `open` syscall, then a `read` syscall. The
kernel checks the file's permissions against the app's user (Chapter 3), and only then
returns the data. **This permission check is the core of app isolation.**

---

# CHAPTER 3 — Users, permissions, and the app sandbox

This chapter is the heart of Android security. Understand it well.

## 3.1 Users and UIDs in Linux

In Linux, every user has a number called a **UID** (user ID). Files are owned by a user,
and each file has **permissions** that say what the owner, the owner's group, and everyone
else may do with it (read, write, execute).

On a normal Linux computer, many programs run as the **same** user (you). That means your
programs can read each other's files. That would be dangerous on a phone full of apps from
different companies.

## 3.2 Android's twist: one user per app

Android changes this: **each installed app gets its own, unique UID.** The app runs as that
user, and only that user can read the app's files. This is how Android keeps apps apart,
reusing Linux's existing permission system.

See it directly. Run a shell *as a specific app* and ask who you are:

```
emulator:/ $ run-as com.example.app
emulator:/data/data/com.example.app $ id
uid=10188(u0_a188) gid=10188(u0_a188) groups=10188(u0_a188),3003(inet),9997(everybody)
```

- `uid=10188` — this app's unique user ID. Android gives apps UIDs from 10000 up.
- `u0_a188` — the username Android derives from that UID (`u0` = user 0 / the main phone
  user; `a188` = app number 188, i.e. 10188 − 10000).
- `groups=... 3003(inet) ...` — the **groups** this app belongs to. Groups come from
  **permissions** the app was granted. `inet` (3003) means the app has the INTERNET
  permission, so it is allowed to use the network. (See Chapter 3.5.)

## 3.3 The app's private folder (the sandbox)

When an app is installed, Android creates a private folder for it:

```
/data/data/<package-name>/
```

The **package name** is the app's unique identifier, like `com.whatsapp` or
`com.example.app`. Inside this folder the app keeps its data: settings, databases, files.

Look at the permissions on these folders:

```
emulator:/ # ls -l /data/data | head
drwx------  4 u0_a188  u0_a188  4096 ... com.example.app
drwx------  6 u0_a55   u0_a55   4096 ... com.android.chrome
```

Read the permission string `drwx------`:
- `d` — it is a directory.
- `rwx` (first group) — the **owner** (`u0_a188`) can read, write, and enter it.
- `---` (second group) — the **group** has no access.
- `---` (third group) — **everyone else** has no access.

So only `u0_a188` — the app itself — can get inside `com.example.app`. Chrome's user
(`u0_a55`) cannot. **This is the sandbox: file permissions enforced by the kernel, using
one UID per app.** This is why, to read an app's data during a test, we need either to be
that app's user (`run-as`, works on debuggable apps) or to be **root** (Chapter 3.4).

Two important directories:
- `/data/data/<package>/` — the app's **runtime data** (what it writes while running).
- `/data/app/<package>/` — the app's **static files**, including the installed APK.

## 3.4 Root

**Root** is the UID 0 — the all-powerful "superuser" that can read and write anything,
ignoring normal file permissions. Real phones you buy do not give you root, for safety.
Test devices and emulator images are **rooted** so we can read any app's data and run tools
like a Frida server. "Rooting" a device means gaining this root access.

## 3.5 Permissions become groups

When you install an app, it asks for **permissions** (internet, camera, contacts, storage).
If granted, Android adds the app's process to a matching **group (GID)**, and the kernel
uses that group membership to allow the action. That is what you saw in the `id` output:
the `inet` group corresponds to the INTERNET permission. So "permission" on Android is
enforced partly through Linux group membership and partly through higher-level checks
(Chapter 12).

---

# CHAPTER 4 — SELinux (a second layer of protection)

The file-permission system in Chapter 3 is called **DAC** — Discretionary Access Control.
"Discretionary" means the owner of a file decides who can access it. DAC has a weakness: if
a process runs as root, it can ignore all of it.

Android adds a second, stricter system called **SELinux** (Security-Enhanced Linux), which
is a form of **MAC** — Mandatory Access Control. "Mandatory" means the rules are fixed by
the system and **even root must obey them**.

How it works: every file and every process is given a **label**. A rule set says which
labels may interact. A label looks like this:

```
u:object_r:app_data_file:s0
```

- `u` — SELinux user.
- `object_r` — role.
- `app_data_file` — the **type** (the part that matters most).
- `s0` — sensitivity level.

Example: an app's data files have the type `app_data_file`, and the app process has the
type `untrusted_app`. SELinux rules allow `untrusted_app` to read/write `app_data_file`,
but **not** to read, say, `system_data_file`. So even if an app found a way to act as root,
SELinux rules would still block it from touching system files it has no rule for.

**Why it matters to us:** SELinux is why some actions fail even with root, and it is part of
why Android is hard to fully compromise. For app testing, you mostly work within what your
rooted test device allows; just know SELinux exists and can be the reason an operation is
denied.

---

# CHAPTER 5 — The Android software stack (the layers)

Android is built in layers. Each layer only talks to the one below it. From bottom to top:

1. **Linux kernel** — manages hardware, memory, processes (Chapters 2–4).
2. **Hardware Abstraction Layer (HAL)** — a standard set of interfaces for hardware. Phone
   makers use different chips (different camera, Bluetooth, fingerprint hardware). The HAL
   hides those differences behind a common interface, so the layers above do not need to
   know the exact chip. Example: there is a "camera HAL" interface; each manufacturer
   provides the code behind it for their camera.
3. **Native libraries** — fast building blocks written in C/C++. Examples: **SQLite** (a
   small database engine used by almost every app to store data) and a web-rendering engine
   used by WebViews. These run directly as machine code, so they are fast.
4. **Android Runtime (ART)** — runs the compiled code of normal apps (Chapter 7).
5. **Java API Framework** — the large set of ready-made code that apps use to do things:
   show screens, use the camera, access the network, share data. App developers call this
   framework instead of talking to hardware directly.
6. **Apps** — what users install and run.

A concrete example — an app takes a photo:
1. The app calls the **camera API** in the Java framework ("take a picture").
2. The framework passes the request down toward the hardware.
3. It reaches the **camera HAL**, the standard camera interface.
4. The HAL's manufacturer code talks to the **kernel's camera driver**.
5. The driver controls the actual **camera hardware**, which captures the image.
6. The image travels back up the layers to the app.

The app never needed to know which camera chip the phone has. That is the point of the
layers.

---

# CHAPTER 6 — What an app is: the APK file

An Android app ships as an **APK** file (Android Package). An APK is just a **ZIP archive**
— a single file that bundles many files together, compressed. You can list its contents
like any ZIP:

```
$ unzip -l app.apk
  Length      Name
---------  ----------------------------------
     3104   AndroidManifest.xml
  2847120   classes.dex
   845300   resources.arsc
      ...   res/layout/activity_main.xml
      ...   res/drawable/icon.png
      ...   lib/arm64-v8a/libnative.so
      ...   assets/config.json
      ...   META-INF/CERT.RSA
```

What each part is:
- **`AndroidManifest.xml`** — the app's configuration file: its name, its components, the
  permissions it needs, which screen starts first (Chapter 9). *Stored in a compact form
  called binary XML — Chapter 6.1.*
- **`classes.dex`** — the app's **compiled code** (Chapter 7). This is where the program
  logic lives.
- **`resources.arsc`** — compiled **resources**: text strings, colours, dimensions
  (Chapter 11).
- **`res/`** — resource files: screen layouts (XML), images, icons.
- **`lib/`** — **native libraries** (`.so` files), one folder per processor type
  (`arm64-v8a`, `armeabi-v7a`, `x86_64`). These are C/C++ code compiled to machine code.
- **`assets/`** — raw files the developer bundled (fonts, config files, sometimes extra
  code or data).
- **`META-INF/`** — the **signature** that proves who built the app (Chapter 13).

**Why it matters to us:** because everything the app needs is inside this one archive, we
can unpack it and examine the code, the strings, the config, and the native libraries. This
is the basis of static analysis (Chapter 13).

## 6.1 What is binary XML?

You already know XML as readable text, like:

```xml
<activity android:name=".MainActivity" android:exported="true" />
```

XML is easy for humans to read but **slow and bulky for a phone to parse** every time the
app runs. So Android **compiles** the XML files (the manifest and the files in `res/`) into
a compact, pre-processed binary form called **binary XML** (or AXML). Instead of storing
the text of each tag and attribute name over and over, binary XML stores them once in a
table of strings and then refers to them by number, plus the structure in a form the system
can read instantly.

The consequence: if you pull `AndroidManifest.xml` straight out of an APK and open it, you
do **not** see readable XML. You see binary data:

```
$ unzip -p app.apk AndroidManifest.xml | xxd | head -2
00000000: 0300 0800 7c0c 0000 0100 1c00 ... ..|.........
00000010: 2e00 0000 6d00 0000 ... m.a.n.i.f.e.s.t.
```

The first bytes (`03 00 08 00`) are a header that marks this as compiled XML; the readable
words you can half-see (`manifest`, `android`) are entries in its string table.

To read it, you **decode** it back to normal XML with a tool. Any of these work:
- `apktool d app.apk` → produces a readable `AndroidManifest.xml`.
- `jadx-gui app.apk` → shows the decoded manifest and resources.
- `aapt dump xmltree app.apk AndroidManifest.xml` → prints the decoded tree.

So "binary XML" is simply **XML that has been compiled into a compact binary format for
speed; we decode it back to text to read it.** You will meet it for the manifest and for the
layout files under `res/`.

---

# CHAPTER 7 — How app code is compiled and run (bytecode, DEX, Dalvik, ART)

This explains what is inside `classes.dex` and how it runs. It answers *why we can
decompile apps.*

## 7.1 Source code, machine code, and bytecode

- **Source code** is what the developer writes, in **Java** or **Kotlin** — readable text.
- **Machine code** is the raw numbers the processor actually executes — specific to a
  processor type, not human-readable.
- Between the two there is **bytecode**: a compiled, compact instruction set that is **not**
  tied to one processor. Bytecode cannot run on the processor by itself; it needs a
  **runtime** program to execute it.

Why have bytecode at all? **Portability.** There are many different phone processors. If
apps shipped as machine code, a developer would need a separate build for each. Instead,
apps ship as bytecode, and each device's runtime turns that bytecode into the right machine
code for its own processor.

## 7.2 From source to the APK

For a normal Java program: `source (.java)` → compiler → `Java bytecode (.class)` → runs on
the Java Virtual Machine.

Android adds one step, because Android does not use `.class` files directly. It uses a more
compact format called **DEX** (Dalvik Executable):

`source (.java/.kt)` → compiler → `Java bytecode (.class)` → **converted to Dalvik
bytecode** → packaged as `classes.dex` inside the APK.

So `classes.dex` contains **Dalvik bytecode** — the app's compiled logic in Android's
format.

## 7.3 Dalvik vs ART (what runs the bytecode)

- **Dalvik** was the old runtime. It used **Just-In-Time (JIT)** compilation: while the app
  ran, Dalvik translated bytecode to machine code **line by line, on the fly**. This made
  apps start quickly but run a bit slower, because translation happened during use.
- **ART** (Android Runtime) replaced it. ART uses **Ahead-Of-Time (AOT)** compilation: at
  **install time**, it translates the whole `.dex` into machine code once and saves it
  (files with the `.oat` extension, produced by a tool called `dex2oat`). The app then runs
  as ready machine code, so it starts and runs faster; the trade-off is a slightly longer
  install.

## 7.4 Smali — readable bytecode

Dalvik bytecode is not readable by itself. **Smali** is a human-readable text form of that
bytecode (think of it as the "assembly language" for DEX). When you decompile with
`apktool`, you get smali. Here is a tiny example — a method that returns the number 42:

```smali
.method public getAnswer()I
    .registers 2
    const/16 v0, 0x2a      # put 42 (0x2a) into register v0
    return v0              # return v0
.end method
```

You will edit smali when you need to modify an app (for example to inject the Frida gadget
in Chapter 27). For *reading* code, **jadx** is easier because it converts the bytecode back
into near-original **Java**, which is far more readable than smali.

## 7.5 Why this means apps can be decompiled

Because the app ships as **bytecode** (a documented, reversible format), tools can convert
it back into readable code — smali (apktool) or Java (jadx). The original comments and some
names may be lost, but the logic is fully recoverable. **This is why static analysis works
and why secrets hidden in an app can be found.**

---

# CHAPTER 8 — How an app starts and runs

1. When Android boots, the kernel starts `init` (PID 1), which starts system services and a
   special process called **Zygote**.
2. **Zygote** is a process that has already loaded the common Android framework code into
   memory. When you tap an app, Android does not build a new process from scratch — it
   **forks** (copies) Zygote. The copy already contains the framework, so the app starts
   fast. The copy is then given the app's **UID** (Chapter 3) and becomes the app's process.
3. Android reads the app's **manifest** to find the **entry point** — the first screen to
   open. The manifest marks one activity with the `MAIN` action and `LAUNCHER` category
   (Chapter 9); that activity (commonly named `MainActivity`) is launched first.
4. From there the app runs: it shows screens, responds to taps, and does work, all through
   the framework (Chapter 5).

So tapping an icon leads to: fork Zygote → assign the app's UID → launch the manifest's
entry activity.

---

# CHAPTER 9 — The building blocks of an app: components

An app is not one single program; it is built from **components**. There are four types.
They are all declared in the manifest. Understanding them is essential because **most app
attacks target components that are exposed to other apps.**

## 9.1 Activity — a screen

An **activity** is a single screen the user sees and interacts with: a login screen, a home
screen, a settings screen. An app is usually many activities.

In the manifest:

```xml
<activity android:name=".MainActivity">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>
</activity>
```

The `MAIN` + `LAUNCHER` lines mark this as the **first** activity to open when the app is
launched (Chapter 8).

Activities have a **lifecycle** — the stages a screen goes through: created, started,
visible, paused, stopped, destroyed. The framework calls methods named `onCreate()`,
`onStart()`, `onResume()`, `onPause()`, `onStop()`, `onDestroy()` at each stage, where the
developer puts code to run at that point. (A **fragment** is a reusable piece of a screen
that lives inside an activity and has its own similar lifecycle.)

## 9.2 Service — background work

A **service** runs in the background with **no screen**, for long tasks like downloading a
file or playing music.

```xml
<service android:name=".SyncService" />
```

## 9.3 Broadcast receiver — an event listener

A **broadcast** is a message announcing that something happened. The system sends
broadcasts for events like "battery low," "screen turned on," or "network changed." Apps can
also send their own broadcasts. A **broadcast receiver** is a component that listens for
particular broadcasts and runs code when one arrives.

```xml
<receiver android:name=".BatteryLowReceiver">
    <intent-filter>
        <action android:name="android.intent.action.BATTERY_LOW" />
    </intent-filter>
</receiver>
```

This receiver runs whenever the system broadcasts `BATTERY_LOW`. The `<intent-filter>` says
which broadcasts it listens for.

## 9.4 Content provider — sharing data between apps

A **content provider** lets one app share structured data with other apps, through a special
address that starts with `content://`. For example, the Contacts app exposes a content
provider so other apps can read contacts (with permission).

```xml
<provider
    android:name=".NotesProvider"
    android:authorities="com.example.app.provider"
    android:exported="false" />
```

The `authorities` value is the provider's unique name; the address other apps use is
`content://com.example.app.provider/...`.

## 9.5 Intents — the messages that connect components

An **intent** is a message used to start an activity or service, or to deliver a broadcast.
There are two kinds:
- **Explicit intent** — names the exact component to start ("open `MainActivity` in this
  app"). Used within an app.
- **Implicit intent** — describes an **action** instead of a specific app ("open this
  URL"), and lets the system pick an app that can handle it.

Example of an implicit intent in action: you tap a link, the app sends an implicit intent
"VIEW this URL," and Android shows a chooser with Chrome and Firefox — the browsers that
declared (via an intent filter) that they can handle web links. You pick one; the intent is
delivered to it; it opens the URL.

## 9.6 Intent filters — what a component will accept

An **intent filter** (`<intent-filter>` in the manifest) declares which intents a component
is willing to receive — which actions, data types, or URL schemes. The `MAIN`/`LAUNCHER`
filter and the `BATTERY_LOW` filter above are examples.

## 9.7 `exported` — the most important security attribute

Each component has an `android:exported` attribute:
- `exported="true"` — **other apps can start or access this component.**
- `exported="false"` — only this app can.

A subtle rule: if a component has an `<intent-filter>` and does not set `exported`, then on
older `targetSdk` versions it is **exported by default**. On newer versions you must set
`exported` explicitly.

**Why it matters:** every exported component is a door into the app that another app (or you,
with `adb`) can use, **skipping the normal user flow.** If a developer assumed a screen could
only be reached after login but left it exported, you can open it directly. Chapters 14–19
are mostly about abusing exported components. This single attribute is the root of a large
share of Android vulnerabilities.

---

# CHAPTER 10 — The manifest, line by line

`AndroidManifest.xml` is the app's configuration. Reading it tells you the attack surface
before you look at any code. Here is a realistic manifest with every part explained:

```xml
<manifest package="com.example.app"
          android:versionCode="12" android:versionName="2.3">

    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="31" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />

    <application
        android:allowBackup="true"
        android:debuggable="false"
        android:usesCleartextTraffic="false"
        android:networkSecurityConfig="@xml/network_security_config"
        android:label="@string/app_name"
        android:icon="@drawable/ic_launcher">

        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <activity android:name=".AdminActivity" android:exported="true" />

        <service android:name=".SyncService" android:exported="false" />

        <receiver android:name=".SmsReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.provider.Telephony.SMS_RECEIVED" />
            </intent-filter>
        </receiver>

        <provider android:name=".NotesProvider"
                  android:authorities="com.example.app.provider"
                  android:exported="true" />
    </application>
</manifest>
```

What a tester notes here:
- `package="com.example.app"` — the app's identity; its data is in `/data/data/com.example.app`.
- `minSdkVersion="21"` — runs on Android 5.0 and up; older versions allow weaker behaviour.
- `targetSdkVersion="31"` — the Android version it was built for; affects default `exported`
  behaviour and other security defaults.
- `INTERNET`, `READ_CONTACTS` — what it can access. Judge each against what the app should
  need. `READ_CONTACTS` is sensitive.
- `allowBackup="true"` — its data can be extracted with `adb backup` without root
  (Chapter 16).
- `debuggable="false"` — good; if it were `true` you could attach a debugger and use
  `run-as` freely.
- `usesCleartextTraffic="false"` + `networkSecurityConfig` — network security settings
  (Chapter 26); read the referenced config file.
- `AdminActivity exported="true"` — **a protected-looking screen reachable by anyone**
  (Chapter 14).
- `SmsReceiver exported="true"` — can receive SMS broadcasts; check what it does with them
  (Chapter 15).
- `NotesProvider exported="true"` — other apps can query it; test for data exposure, SQL
  injection, and path traversal (Chapter 17).

---

# CHAPTER 11 — Resources and how strings work

**Resources** are the non-code parts of an app: text strings, images, layouts, colours.
Keeping them separate from code lets the app support multiple languages and screen sizes.

- `res/values/strings.xml` holds text strings:
  ```xml
  <resources>
      <string name="app_name">Example App</string>
      <string name="api_base">https://api.example.com/</string>
  </resources>
  ```
- In code, a string is referenced by a generated ID, not by its text:
  ```java
  String url = getString(R.string.api_base);   // looks up "api_base"
  ```
  `R` is an auto-generated class holding numeric IDs for every resource; `R.string.api_base`
  is the ID for that string.
- `resources.arsc` is the **compiled** table of all these values (the binary form of the
  `res/values` files). When you decompile with jadx/apktool you can read the original
  `strings.xml`.

**Why it matters:** developers often put secrets (URLs, API keys, even passwords) in
`strings.xml` thinking it is "not in the code." It is trivially readable after decompiling.
Searching strings is one of the most productive early steps (Chapter 13).

---

# CHAPTER 12 — Permissions, in more depth

A **permission** is the app's request to do something sensitive. Categories:
- **Normal permissions** (e.g. INTERNET, VIBRATE) — low risk; granted automatically at
  install.
- **Dangerous permissions** (e.g. READ_CONTACTS, CAMERA, LOCATION, READ/WRITE external
  storage) — must be approved by the user **at runtime** (a popup) on modern Android.
- **Signature permissions** — only granted to apps signed by the same developer; used to
  share data safely between a company's own apps.

As shown in Chapter 3, some permissions map to Linux **groups** (INTERNET → `inet`), so the
kernel can enforce them; others are checked higher up by the framework. Custom permissions
can also protect a developer's own components (for example requiring a permission to send a
broadcast to a receiver), which is a defence against the component attacks in Chapters
14–17.

---

# CHAPTER 13 — Signing (and why we must re-sign modified apps)

**Signing** proves who built the app and that it has not been changed since. How it works:
1. The developer computes a **hash** of the app — a short fingerprint where any change to
   the app produces a completely different hash.
2. The developer **encrypts that hash with their private key** (a secret only they hold).
   The encrypted hash is the **digital signature**, stored in the APK (`META-INF/`).
3. When the app is installed, Android **decrypts the signature with the matching public key**
   and compares it to a fresh hash of the app. If they match, the app is authentic and
   unmodified.

Signing schemes by Android version: **v1** (each file signed, stored in `META-INF`), **v2**
(the whole APK signed as one block, Android 7+), **v3** (adds key rotation, Android 9+).

**Why it matters to us:** when we modify an app — for example to inject a Frida gadget to
bypass SSL pinning (Chapter 27) — the app no longer matches its original signature, so it
will not install. We must **re-sign** it with our own key first. The steps (keytool →
apksigner → zipalign) are in Chapter 24.

---

# CHAPTER 14 onward — THE ATTACKS

From here, each chapter follows the same shape:
**what it is → why it is vulnerable → techniques (with commands and examples).**

The order follows how you test: first data stored on the device, then the app's exposed
entry points, then WebViews, then the network and crypto, then on-device authentication,
then runtime and UI, then the backend.

---

# CHAPTER 14 — Insecure data storage

**What it is.** The app saves sensitive data on the device (passwords, authentication
tokens, encryption keys, personal data) in a form that can be read — plain text, or weak
encoding like Base64 that only looks protected.

**Why it is vulnerable.** The sandbox (Chapter 3) protects these files from *other apps*,
but it does **not** protect them from someone who has the device with root, a backup of it,
or malware that gains file access. If the data is stored unencrypted, reading the file gives
the secret directly. The correct approach is to encrypt sensitive data with a key held in
the **Android Keystore** (Chapter 9 of your original notes / Chapter 29 here), so the file
is useless without the hardware-protected key. Storing it in plain text removes that
protection entirely.

**Where the data lives** (under `/data/data/<package>/`):
- `shared_prefs/` — small settings saved as XML.
- `databases/` — SQLite database files.
- `files/` and `cache/` — files the app writes.
- External storage `/sdcard/Android/data/<package>/` — weaker, since other apps could read
  it on older Android.

**Techniques.**
1. Get into the app's folder (root, or `run-as` on a debuggable app):
   ```
   adb shell
   run-as com.example.app
   cd /data/data/com.example.app
   ls -la
   ```
2. Read the shared preferences and look for secrets:
   ```
   cat shared_prefs/*.xml
   ```
   A real finding looks like:
   ```xml
   <map>
     <string name="auth_token">eyJhbGciOiJIUzI1Ni...</string>
     <string name="username">john</string>
     <string name="password">Summer2026!</string>
   </map>
   ```
   A password or token in plain text here is the vulnerability.
3. Open databases and dump tables:
   ```
   sqlite3 databases/app.db
   .tables
   SELECT * FROM users;
   ```
4. Inspect files/cache; use `strings` for binary files:
   ```
   strings files/session.dat | grep -iE "token|key|password"
   ```
5. Check external storage for anything sensitive.

**Finding and fix.** Any sensitive value readable this way is the finding. Fix: store it
encrypted using the Android Keystore / EncryptedSharedPreferences.

---

# CHAPTER 15 — Insecure logging

**What it is.** The app writes sensitive data into the system log while it runs.

**Why it is vulnerable.** Logs exist for debugging and are easy to read on a device you
control; on older Android other apps could read them too. Developers frequently leave
debug logging (printing a token or password to check their code) in the released app by
mistake. Anything in the log can be read without breaking any protection.

**Techniques.**
```
adb logcat                                       # watch the live log
adb logcat | grep -iE "password|token|pin|card|otp|secret"
```
Open the app and move through each screen (log in, make a payment, view the profile) while
watching. If a secret appears — for example `D/Login: sending password=Summer2026!` — note
the exact screen/action. **Fix:** remove or mask sensitive logging in release builds.

---

# CHAPTER 16 — Backup extraction

**What it is.** If the manifest has `android:allowBackup="true"` (the default when not set),
the app's private data can be copied off the device with `adb` — **without root**.

**Why it is vulnerable.** It provides a way around the sandbox: someone with brief physical
access and USB debugging enabled can pull the app's private files, which are supposed to be
reachable only by the app's own UID. If those files contain secrets (Chapter 14), they are
now exposed.

**Techniques.**
```
adb backup -f backup.ab -noapk com.example.app      # confirm the prompt on the device
java -jar abe.jar unpack backup.ab backup.tar        # convert the .ab to a tar archive
tar xvf backup.tar
```
Then read the extracted `shared_prefs`/`databases`/`files` as in Chapter 14. **Fix:** set
`allowBackup="false"`, or exclude sensitive files from backup.

---

# CHAPTER 17 — Exported activity exploitation

**What it is.** An exported activity (Chapter 9.7) can be opened directly by any app or by
`adb`. If the app relied on its normal screen order for security, opening a screen directly
can skip steps such as login.

**Why it is vulnerable.** Developers sometimes enforce access only by *flow* — "you can only
reach the account screen by first passing the login screen." But an exported activity can be
launched out of order, so that assumption breaks. On top of that, activities read **intent
extras** (data passed in when they are started); if the activity trusts an extra to decide
access (for example a boolean `isLoggedIn`), an attacker can supply it.

**Techniques.**
1. Find exported activities in the manifest (Chapter 10). Example target: `AdminActivity`.
2. Open it directly:
   ```
   adb shell am start -n com.example.app/.AdminActivity
   ```
   `am start` asks Android to open that exact screen. If the admin screen appears without
   logging in, that is broken access control.
3. Pass crafted extras to influence its logic:
   ```
   am start -n com.example.app/.AdminActivity --es role admin --ez isLoggedIn true --ei userId 1
   ```
   `--es` = string extra, `--ez` = boolean, `--ei` = integer. If the screen treats
   `isLoggedIn true` as logged in, the control is bypassed.
4. Record what the screen shows or does. **Fix:** don't export it, re-check authentication
   on the server, and never trust intent extras for access decisions.

---

# CHAPTER 18 — Broadcast receiver exploitation

**What it is.** An exported broadcast receiver (Chapter 9.3) will act on a broadcast sent by
any app. You can send it a crafted broadcast to trigger whatever it does.

**Why it is vulnerable.** A receiver is meant to react to a trusted event. If it is exported
and performs a sensitive action when it receives its message — unlocking a feature, marking
something paid, changing a setting — then an attacker who sends that same message gets the
action for free. The receiver trusted the *message* instead of verifying *who sent it.*

**Techniques.**
1. Find exported receivers and the action they listen for (Chapter 10).
2. Send a crafted broadcast:
   ```
   adb shell am broadcast -a com.example.app.ACTION_UNLOCK --es code "0000" -n com.example.app/.UnlockReceiver
   ```
3. Observe the effect; if a privileged action happens, that is the finding. **Fix:** don't
   export, or require a permission to send to the receiver, and validate the input.

---

# CHAPTER 19 — Service exploitation

**What it is.** An exported service (Chapter 9.2) can be started by any app, making its
background functionality reachable without the UI.

**Why it is vulnerable.** Services often do privileged internal work. If exported, that work
can be invoked directly with attacker-chosen input, skipping any checks the UI would have
done.

**Techniques.**
1. Find exported services (Chapter 10).
2. Start one with input:
   ```
   adb shell am startservice -n com.example.app/.CommandService --es cmd "reset_pin"
   ```
3. See what it does with your input. **Fix:** don't export, or protect with a permission and
   validate input.

---

# CHAPTER 20 — Content provider exploitation (SQL injection and path traversal)

**What it is.** A content provider (Chapter 9.4) shares data through a `content://` address.
If it is exported or misconfigured, other apps can read or write its data. Two specific bugs
occur here: **SQL injection** and **path traversal**.

**Why it is vulnerable.**
- Many providers answer a query by building a database query from text the caller supplies
  (the "selection," i.e. the WHERE clause). If the provider inserts that text directly into
  the SQL instead of using safe parameters, the caller can change the meaning of the query —
  this is **SQL injection**. For example, supplying `1=1` as the selection makes the WHERE
  clause always true, returning every row.
- Some providers return **files** by building a file path from the caller's input. If they
  do not check the path, the caller can include `../` sequences to climb out of the intended
  folder and read other files — this is **path traversal**. For example, requesting
  `../../../../data/data/<pkg>/shared_prefs/prefs.xml` reads the app's private prefs.

**Techniques.**
1. Find the provider's address: `android:authorities` in the manifest →
   `content://<authority>/`.
2. Query it to see if it returns data without permission:
   ```
   adb shell content query --uri content://com.example.app.provider/users
   ```
3. Test SQL injection in the selection:
   ```
   adb shell content query --uri content://com.example.app.provider/users --where "1=1"
   adb shell content query --uri content://com.example.app.provider/users \
       --where "1=1) UNION SELECT name,sql FROM sqlite_master--"
   ```
   If `1=1` returns all rows, or the UNION returns database structure, it is injectable.
4. Test path traversal on file-serving providers:
   ```
   adb shell content read --uri "content://com.example.app.provider/../../../../data/data/com.example.app/shared_prefs/prefs.xml"
   ```
5. Automate with **drozer** (install the drozer agent APK, then
   `adb forward tcp:31415 tcp:31415` and `drozer console connect`):
   ```
   run app.provider.info -a com.example.app
   run scanner.provider.injection -a com.example.app
   run scanner.provider.traversal -a com.example.app
   ```
   drozer tests every provider quickly — worth learning for this chapter.
**Fix:** don't export unneeded providers; use parameterised queries; validate file paths.

---

# CHAPTER 21 — Deep links and intent redirection

**What it is.** A **deep link** is a URL that opens the app at a specific screen, e.g.
`myapp://account?id=5`. The app registers these in the manifest. Any source — another app, a
web page, a QR code — can send a deep link to the app.

**Why it is vulnerable.** The data inside a deep link comes from **outside** the app and is
attacker-controllable, but apps often trust it. Three common problems: the link's parameters
reach a database query, a file path, or an access decision (so you can inject or access other
users' data); a parameter is a URL that the app loads in a WebView (so an attacker can make
the app display their page — Chapter 22); or the app forwards an attacker-supplied intent to
an internal component, letting the attacker reach components they could not reach directly
(**intent redirection**).

**Techniques.**
1. Find deep links in the manifest: `<intent-filter>` with
   `<data android:scheme="myapp" .../>`.
2. Trigger one with adb:
   ```
   adb shell am start -a android.intent.action.VIEW -d "myapp://account?id=5" com.example.app
   ```
3. Test the parameters: change `id` to see other users' data (access control); inject SQL,
   path, or URL values to see where they flow; point a URL parameter at a page you control to
   test a WebView redirect. **Fix:** validate every value from a deep link; never use it for
   access decisions or to build queries/paths/URLs unchecked.

---

# CHAPTER 22 — WebView attacks

**What it is.** A **WebView** is a web-browser window embedded inside the app to show web
pages. WebViews have settings that, if enabled carelessly, let the web page call the app's
own code or read local files.

**Why it is vulnerable.** The danger appears when an attacker can control the page shown in
the WebView (via a deep link, an in-app link, or network interception). Then:
- **`addJavascriptInterface`** exposes a Java object to the page's JavaScript so the page can
  call app methods. On old `targetSdk` (<17) this allowed full code execution; even now, if
  the exposed methods are risky, the page can call them — attacker web content runs app code.
- **File access settings** (`setAllowFileAccess`, `setAllowUniversalAccessFromFileURLs`) let
  a page open `file://` URLs and read the app's private files.
- **JavaScript enabled with untrusted content** allows script injection (XSS) inside the app,
  and with a bridge, native calls.
- **Ignoring certificate errors** (`onReceivedSslError` → `handler.proceed()`) lets a
  man-in-the-middle feed the WebView a malicious page.

**Techniques (check each in the decompiled code with jadx).**
1. Search for `addJavascriptInterface`; read the exposed class and its `@JavascriptInterface`
   methods. If you can load your page in the WebView, call those methods from your JavaScript:
   ```javascript
   // in a page the WebView loads
   window.AndroidBridge.doSomething("test");
   ```
2. Search for `setAllowFileAccess(true)` / `setAllowUniversalAccessFromFileURLs(true)`. If on,
   load a page that reads `file:///data/data/com.example.app/shared_prefs/prefs.xml`.
3. Find where the WebView's URL or HTML comes from; if any of it is input you control, inject
   a script and confirm it runs.
4. Search for `onReceivedSslError`; if it proceeds on error, note it.
**Fix:** avoid JS bridges (keep exposed methods safe), disable file access, load only trusted
URLs, never ignore SSL errors.

---

# CHAPTER 23 — Intercepting network traffic

**What it is.** To test what the app sends and receives, you route its traffic through a
**proxy** (Burp Suite) so you can see and change every request. This chapter sets that up;
Chapter 24 handles apps that block it with SSL pinning.

**Why you need it.** Most serious bugs are in the server the app talks to (Chapter 31). You
can only test the server if you can see the app's requests. Interception is the gateway to
all network and API testing.

**Techniques.**
1. In Burp, add a proxy listener bound to all interfaces (e.g. port 8082) so the device can
   reach it.
2. Set the device/emulator's proxy to your computer's IP and that port.
3. Install **Burp's CA certificate** on the device as a trusted certificate, so normal HTTPS
   is trusted by the device (otherwise the device rejects Burp's interception certificate).
4. Browse the app; requests should appear in Burp. If HTTPS traffic does **not** appear and
   the app errors, the app is likely using **SSL pinning** — go to Chapter 24.

---

# CHAPTER 24 — SSL pinning, and how to bypass it

**What it is.** **TLS** (the "S" in HTTPS) encrypts traffic and lets the app verify the
server using a **certificate**. Normally a device trusts many certificate authorities, so
installing Burp's certificate (Chapter 23) is enough to intercept. **SSL pinning** is an
extra check the app adds: it stores (pins) the exact certificate it expects and refuses any
other — including Burp's. So pinning blocks interception.

**Why we bypass it (and why it is bypassable).** Pinning is a good defence, but it runs
*inside the app, on a device we control*. Since we can modify the app or change its behaviour
at runtime, we can disable the pinning check. We do this not to attack users but to see the
traffic so we can test the backend. Pinning being bypassable is expected — it slows down
casual interception, it does not make the client trustworthy.

**Technique A — objection (easiest).** objection repacks the app with a Frida "gadget" (a
small library that lets us change the app at runtime) and can turn pinning off:
```
objection patchapk --source app.apk        # injects the Frida gadget and re-signs the APK
adb install app.objection.apk
objection explore
android sslpinning disable                   # turn off the pinning check
```
For split APKs:
```
objection patchapk --source base.apk --use-aapt2
objection signapk <each-split>.apk
adb install-multiple base.objection.apk split_config.en.objection.apk
```

**Technique B — Frida server (device is rooted).** Run a Frida server on the device and load
a bypass script against the live app:
```
adb push frida-server-<ver>-android-arm64 /data/local/tmp
adb shell "chmod +x /data/local/tmp/frida-server && /data/local/tmp/frida-server &"
adb shell pm list packages | grep example           # get the exact package
frida -U -f com.example.app -l pinning-bypass.js     # run app with the bypass
```
Ready-made scripts are on **Frida CodeShare** (search "universal SSL pinning bypass").

**Technique C — manual gadget injection (when A fails).**
```
apktool d -r app.apk                                 # decompile to smali
```
- Download the Frida **gadget** `.so` for the device's architecture, rename it
  `libfrida-gadget.so`, and place it in `lib/<arch>/`.
- In the first activity's smali, add code so the gadget loads when the app starts:
  ```smali
  const-string v0, "frida-gadget"
  invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
  ```
- Rebuild, sign, align, install (Chapter 24 signing steps / your notes), then:
  ```
  objection explore
  android sslpinning disable
  ```
The gadget runs inside the app; objection talks to it to change behaviour at runtime.

**Other network weaknesses to check once traffic is visible.**
- **Cleartext:** `usesCleartextTraffic="true"` or any `http://` endpoint — confirm in Burp.
- **Accept-all certificate code:** in the decompiled code, an `X509TrustManager` whose
  `checkServerTrusted` method is empty, or a `HostnameVerifier` that always returns true —
  these break TLS even without pinning, so a man-in-the-middle works.
- **network_security_config.xml:** trusting user-added certificates or leaving
  `debug-overrides` in a release build makes interception easy.

---

# CHAPTER 25 — Flutter app SSL bypass

**What it is.** Apps built with **Flutter** (using the **Dart** language) do not use
Android's normal network code, so the Chapter 24 bypasses do not work. Flutter does its own
TLS with a library called **BoringSSL**, inside `libflutter.so`. The bypass is to force
BoringSSL's certificate-check function to always say "valid."

**How to recognise it.** The `lib/` folder contains `libflutter.so` (the Flutter engine) and
`libapp.so` (your Dart code compiled).

**Why it is more work.** The check is in compiled native code with no names, so you locate it
by analysing the library in **Ghidra** and then hook it by memory address with Frida.

**Techniques.**
1. `apktool d app.apk` to extract the libraries.
2. Open `libflutter.so` in **Ghidra** (new project → import as a shared library → let it
   analyse).
3. In Ghidra, search strings for `ssl_client`/`ssl_server`; the real certificate-check
   function is `session_verify_cert_chain` in BoringSSL. Find the function that references
   that string. The decompiler panel shows C-like code; this function returns true/false for
   whether the certificate is valid.
4. Note its address. Ghidra loads the file at a base of `0x100000`, so the real file
   **offset** is the shown address minus `0x100000`. Example: `0x002ae9ec − 0x100000 =
   0x001ae9ec`.
5. At runtime, find where `libflutter.so` is loaded in memory (its **base address**), add the
   offset, and hook that address with Frida, replacing the return value with 1 (valid):
   ```
   frida -U -f com.example.app -l rootbypass.js -l spoofbuild.js -l flutter_ssl_bypass.js
   ```
   The bypass script finds the library's base, attaches at base+offset, and on the function's
   return does `retval.replace(0x1)` so every certificate is accepted.

---

# CHAPTER 26 — Insecure cryptography

**What it is.** The app uses encryption or hashing, but in a way that can be broken: a weak
algorithm, a key written into the app, a predictable value where randomness is required, or
"encryption" that is really just encoding.

**Why it is vulnerable.** Cryptography only protects data if it is done correctly. A key
inside the app is available to anyone who decompiles it, so the encryption gives no
protection. Weak algorithms (like MD5 or DES) can be broken with known methods. ECB mode
leaks patterns because identical input blocks produce identical output blocks. A fixed IV or
a predictable random value lets an attacker reproduce or undo the encryption. Each of these
turns "encrypted" data back into readable data.

**Techniques (search the decompiled code with jadx).**
1. **Hardcoded keys** — long Base64/hex strings near `SecretKeySpec`, `Cipher`,
   `IvParameterSpec`. Example of a vulnerable line:
   ```java
   SecretKeySpec key = new SecretKeySpec("1234567890123456".getBytes(), "AES");
   ```
   The key is right there in the app.
2. **Weak algorithms** — search for `DES`, `RC4`, `MD5`, `SHA1`, and cipher strings
   containing `ECB`.
3. **Static/reused IV** — a constant passed to `IvParameterSpec`.
4. **Insecure randomness** — `new Random()` or `Math.random()` used for keys/tokens/IVs
   instead of `SecureRandom`.
5. **Keys not in the Keystore** — keys kept in prefs/files (combine with Chapter 14).
Confirm at runtime by hooking the cipher setup with Frida to print the key, IV, and
plaintext.

---

# CHAPTER 27 — Client-side authentication bypass

**What it is.** The app checks a PIN or password **on the device itself** (comparing your
input to a stored value) instead of asking the server.

**Why it is vulnerable.** Any check that runs on the device runs on hardware the attacker
controls, so the attacker can either read the expected value out of the app or change the
app's behaviour so the check always passes. A security decision made only on the client is
never trustworthy. The correct design verifies credentials on the server, where the attacker
cannot change the logic.

**Techniques.**
1. Find the check in the code — an `if` comparing input to a string, a stored hash, or the
   result of a method. (This is the "hardcoded string comparison" pattern from your notes.)
2. Recover the expected value statically: if it is a hardcoded string, an obfuscated string,
   or Base64 in another class, decode it (`echo <b64> | base64 -d` or CyberChef) and use it.
3. Force the check to pass at runtime with Frida:
   ```javascript
   Java.perform(function () {
     var C = Java.use("com.example.app.PinManager");
     C.verifyPin.implementation = function (entered) {
       return true;   // report any PIN as correct
     };
   });
   ```
**Fix:** authenticate on the server.

---

# CHAPTER 28 — Biometric authentication bypass

**What it is.** The app uses fingerprint or face unlock. There are two designs. The **weak**
design only asks the system "did biometric succeed?" and then reveals the protected content;
the result is a simple success/failure the attacker can fake. The **strong** design ties the
biometric to unlocking a key in the Android Keystore, so faking the success gives nothing —
the key stays locked.

**Why the weak design is vulnerable.** If success is just a signal that leads to showing the
data, we can make the app act as if that signal arrived, using Frida, without any
fingerprint. If a Keystore key is required to actually decrypt the data, faking the signal is
useless — which is why the strong design resists this.

**Techniques.**
1. Check which design: if biometric success simply reveals data or navigates forward and no
   Keystore key is used, it is the weak design.
2. Call the success path directly with Frida:
   ```javascript
   Java.perform(function () {
     var cb = Java.use("androidx.biometric.BiometricPrompt$AuthenticationCallback");
     cb.onAuthenticationSucceeded.implementation = function (result) {
       return this.onAuthenticationSucceeded(result);
     };
   });
   ```
   If this unlocks the app, biometric was only a UI gate.
3. If a Keystore key is used, this will not work — note that the app did it correctly.
**Fix:** bind biometric to a Keystore key.

---

# CHAPTER 29 — Runtime manipulation with Frida (general skill)

**What it is.** **Frida** is a tool that lets you read and change an app *while it runs* — you
"hook" a method so that your code runs when that method is called, letting you see its inputs
and output or change its behaviour. SSL/root bypass are specific uses; this is the general
skill behind them.

**Why it is powerful for testing.** Because the app runs on your device, Frida lets you
observe secrets as they are used (keys, decrypted data), change decisions (make a check
pass), and reach hidden code — which is how you confirm and demonstrate many findings.

**Core patterns.**
1. Log a method's inputs and output (to understand it or capture secrets):
   ```javascript
   Java.perform(function () {
     var C = Java.use("com.example.app.Crypto");
     C.decrypt.implementation = function (data) {
       var out = this.decrypt(data);
       console.log("[decrypt] in=" + data + "  out=" + out);
       return out;   // keep normal behaviour, just observe
     };
   });
   ```
2. Change a return value to bypass a check (Chapters 27/28).
3. Call a method directly to decrypt a value or reach hidden functionality.
4. objection shortcuts (built on Frida): `android hooking list classes`,
   `android hooking search methods <keyword>`, `memory dump all`, `sqlite connect`,
   `android keystore list`, `android clipboard monitor`.

---

# CHAPTER 30 — Memory, clipboard, screenshot, and UI leakage

**What it is.** Sensitive data can escape through side channels: it may remain in the app's
**memory** in plain text, be copied to the **clipboard** (which is shared between apps),
appear in a **screenshot** or the app-switcher preview, or be remembered by the keyboard.

**Why it is vulnerable.** These channels are outside the file sandbox. The clipboard is
readable by other apps; the app-switcher thumbnail can capture a screen that shows a secret;
memory can be dumped on a device you control. If the app does not take care to clear
secrets, hide sensitive screens, or block copying, the data leaks through these paths.

**Techniques.**
1. **Memory:** `objection -g com.example.app explore` then `memory dump all ./md`; then
   `strings ./md/* | grep -iE "password|token|card|pin"`. Secrets found here were not cleared
   after use.
2. **Clipboard:** `android clipboard monitor` (objection) while you copy a card number or
   password in the app; if it appears, the app allowed sensitive data to be copied.
3. **Screenshot / app-switcher:** open a sensitive screen, then open the app switcher; if the
   preview shows the data, the screen lacked the `FLAG_SECURE` protection.
4. **Keyboard cache:** password/card fields should set an input type that disables
   suggestions and caching.

---

# CHAPTER 31 — Tapjacking (overlay attacks)

**What it is.** Another app draws a layer on top of this app. The user sees the attacker's
layer (or an invisible one) and their taps are captured by the attacker, or go to this app's
buttons without the user realising what they are confirming.

**Why it is vulnerable.** Android allows apps to draw over others. If a sensitive button does
not protect itself, an overlay can trick the user into pressing it (for example confirming a
payment or granting a permission) while they think they are doing something else.

**Techniques.** Check whether sensitive buttons set
`android:filterTouchesWhenObscured="true"`, which makes Android ignore a touch if something is
drawn over the view at that moment. If this is missing on sensitive actions, the screen can be
attacked with an overlay. **Fix:** set that attribute on sensitive views.

---

# CHAPTER 32 — Resilience: root, emulator, and tamper detection (and bypass)

**What it is.** Defences the app adds to detect an unsafe environment: **root detection**
(is the device rooted?), **emulator detection** (is this an emulator?), **debugger/Frida
detection**, and **tamper/signature checks** (has the app been modified?). When triggered,
the app may refuse to run.

**Why they exist and why we bypass them.** These make it harder to analyse or modify the app.
They are **defence in depth** — they slow an attacker, but they do not fix the real
vulnerabilities in Chapters 14–31. For a test, your job is to **document which defences are
present and whether you can bypass them**, and then continue testing everything else.

**Techniques.**
1. **Root detection:** objection → `android root disable`, or a Frida anti-root script:
   `frida -U -f com.example.app -l antiroot.js`.
2. **Emulator detection:** spoof device properties so the emulator looks like a real phone:
   `frida -U -f com.example.app -l antiroot.js -l spoofbuild.js`.
3. **Combine with pinning:**
   `frida -U -f com.example.app -l antiroot.js -l spoofbuild.js -l pinning-bypass.js`.
4. **Tamper/signature checks:** find the method that verifies the signature and hook it with
   Frida to return the expected value.

---

# CHAPTER 33 — Backend / API testing (where the biggest bugs are)

**What it is.** The app talks to a **server** through an **API** (a set of network endpoints).
The app is only the client; the server holds the accounts, money, and data. Many of the most
serious bugs are on the server, which often trusts the app too much.

**Why it is vulnerable.** Developers sometimes put security checks only in the app (for
example hiding a button), assuming requests always come from their app. But once you can see
and replay the requests (Chapters 23–24), you can send any request directly, skipping the
app's checks. Server weaknesses then affect **every** user, not just your device.

**Techniques.**
1. **Capture traffic:** bypass pinning and proxy the app through Burp so you see every request.
2. **Broken access control / IDOR:** change an identifier in a request (`userId=5` → `6`) and
   see if you get another user's data or perform actions as them.
3. **Authentication / session:** check how tokens are issued and validated — do they expire,
   can they be reused, are JWT signatures verified.
4. **Injection:** test API parameters for SQL, NoSQL, and command injection, as in web
   testing.
5. **Excessive data exposure:** compare what the API returns to what the app displays — the
   API often returns extra fields (other users' data, internal flags).
6. **Business logic:** replay or reorder requests to skip steps (for example confirm an order
   without paying).
Test the API as thoroughly as a web application; this is usually where critical findings are.

---

# CHAPTER 34 — Methodology checklist

**Recon & setup:** obtain APK (pull/sideload, merge splits) · identify stack (lib/) ·
MobSF + apkleaks triage.
**Static:** manifest (exported, backup, debuggable, cleartext, SDK) · hardcoded secrets
(strings.xml, resources, source, assets) · recover obfuscated secrets · cloud/Firebase enum ·
network_security_config.
**On-device data:** shared_prefs · sqlite · files/cache · external storage · logcat per
screen · backup if allowBackup.
**Exposed components:** exported activities + extras · receivers · services · providers
(query, SQLi, traversal) · deep links + parameters.
**WebView:** addJavascriptInterface · file access · untrusted content · SSL errors.
**Network & crypto:** intercept (pinning/Flutter bypass) · cleartext · cert/hostname
validation · config · hardcoded keys/weak algos/static IV/weak random.
**Auth on device:** client-side auth bypass · biometric bypass.
**Runtime & UI:** memory dump · clipboard/screenshot/keyboard · tapjacking.
**Backend/API:** IDOR/access control · auth/session · injection · excessive data · logic.
**Resilience:** root/emulator/Frida/tamper detection documented + bypass notes.
**Report:** each finding — title, MASVS category, severity, proof, impact, remediation.

---

## References
- OWASP MASTG / MASVS — https://mas.owasp.org/
- drozer — https://github.com/WithSecureLabs/drozer
- Frida — https://frida.re/ · objection — https://github.com/sensepost/objection
- Frida CodeShare — https://codeshare.frida.re/
- Practice apps: InjuredAndroid, DIVA, Pivaa, drozer "sieve"
