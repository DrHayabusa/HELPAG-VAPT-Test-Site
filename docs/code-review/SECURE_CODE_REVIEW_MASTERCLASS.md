# Secure Code Review — Masterclass (from zero)

This is a complete, from-scratch study book for **secure source code review**. It assumes
you already understand web/mobile security concepts (XSS, SQL injection, access control),
but assumes **no programming knowledge at all**. Every term is explained the first time it
appears, with real examples. It is written to be read top to bottom.

The job you are preparing for: review the **source code** of applications written in
**TypeScript, C#, and Java**, by hand and with automated tools (including **Black Duck**),
and find security bugs — the same bug classes you find in pentesting, but spotted in the
**code** instead of by attacking a running app.

**Structure.**
- **Part 1 — Chapters 1–5: Foundations** — programming languages, frontend vs backend,
  codebases, functions, source vs compiled code.
- **Part 2 — Chapters 6–9: The languages & frameworks you'll review** — JavaScript &
  TypeScript, Java, C#/.NET/ASP.NET, and the frameworks (Node.js, React, Angular, Next.js).
- **Part 3 — Chapters 10–13: Code review itself** — what it is, manual technique
  (sources & sinks), automated tools (SAST/SCA/DAST), and **what Black Duck is**.
- **Part 4 — Chapter 14: OWASP Top 10 in the code** — for each item: what vulnerable code
  looks like and what to search for, across TypeScript, Java, and C#.
- **Part 5 — Chapters 15–16: Methodology & checklist.**

---

# PART 1 — FOUNDATIONS

# CHAPTER 1 — What is a programming language?

A **computer** only understands numbers — on/off signals (1s and 0s). Telling it what to do
in raw numbers is impossible for humans. A **programming language** is a human-readable way
to write instructions, which are then translated into those numbers for the computer to run.

So a programming language is **a set of words and rules for writing instructions a computer
can carry out.** The instructions you write are called **code** (or **source code**).

A tiny example (in a made-up but typical style):
```
price = 100
tax = price * 0.05
total = price + tax
print(total)          // shows 105
```
Each line is an **instruction**. Together they are a **program**. The language defines what
words like `print` mean and how you're allowed to write them (the **syntax** — the grammar
of the language).

**Why this matters for security.** Bugs live in these instructions. If a line takes input
from a user and builds a database query by gluing text together, that's where SQL injection
hides. Code review = reading these instructions and spotting the dangerous ones.

**Two families of languages (you'll meet both):**
- **Compiled** — the code is translated **once**, ahead of time, into the computer's number
  language, producing a file the machine runs directly. Java and C# work this way.
- **Interpreted** — the code is translated **line by line as it runs**, by another program.
  JavaScript works this way.

(More on this in Chapter 5.)

---

# CHAPTER 2 — Frontend and backend

Almost every application has two halves. Understanding which half a piece of code belongs to
tells you which bugs to look for.

**Frontend (the client side).**
The part that runs **on the user's device** — in their browser (for a website) or in the app
(for mobile). It is what the user **sees and clicks**: buttons, forms, pages. It is written
in languages the browser understands (HTML, CSS, and **JavaScript/TypeScript**).

Key security fact: **the frontend is fully controlled by the user.** They can read all of it,
change it, and skip it. So **any security check done only in the frontend is worthless** —
an attacker just bypasses it. This single fact drives many code-review findings.

**Backend (the server side).**
The part that runs **on the company's server**, which the user cannot see or change. It holds
the real logic, the database, the accounts, and the money. It is written in **Java, C#,
Node.js**, and similar. This is where the **real** security must be: authentication,
authorization, input validation, database access.

**How they talk.** The frontend sends a **request** over the network (an **API call**) to the
backend; the backend does the work and sends back a **response** (usually **JSON** — a simple
text format for data). You already know this from pentesting: the requests you see in Burp are
the frontend talking to the backend.

```
[ Browser / Mobile app ]  --- request --->  [ Server ]  <--->  [ Database ]
      FRONTEND                                 BACKEND
   HTML/CSS/JS/TS                          Java / C# / Node.js
   user controls this                      user cannot see this
```

**Why this matters.** When you review code, first ask **"is this frontend or backend?"**
- A validation or access check in the **frontend** → note it, but it protects nothing.
- The same check missing in the **backend** → that's the real vulnerability.

---

# CHAPTER 3 — What is a codebase?

A **codebase** is **all the source code files of an application, together** — usually
organized in folders, and stored in a **repository** (a project folder tracked by a tool
called **git**, often hosted on GitHub/GitLab).

A real codebase is not one file; it's hundreds or thousands, in a folder tree like:
```
myapp/
├── src/                 # the actual source code
│   ├── controllers/     # code that handles incoming requests
│   ├── services/        # business logic
│   ├── models/          # database shapes
│   └── utils/           # helpers
├── package.json         # (Node/JS) list of third-party libraries used
├── pom.xml              # (Java) list of third-party libraries used
├── *.csproj             # (C#) list of third-party libraries used
└── README.md            # documentation
```

Things you'll care about in a codebase:
- **`src/`** — where the app's own code lives (you read this for logic bugs).
- **Dependency files** (`package.json`, `pom.xml`, `*.csproj`) — the list of **third-party
  libraries** the app uses. **This is what Black Duck scans** (Chapter 13).
- **Config files** (`.env`, `appsettings.json`, `application.properties`) — settings and,
  too often, **hardcoded secrets**.

**How to move around a codebase (your main manual skill).**
You rarely read a codebase top to bottom. You **search** it. The most important tool is
**grep** (search text across all files):
```
grep -rn "password" .           # find the word password everywhere
grep -rniE "exec|eval|query" .  # find several dangerous words, case-insensitive
```
`-r` = search all files in all subfolders, `-n` = show line numbers, `-i` = ignore case,
`-E` = allow multiple patterns. You'll use grep constantly. Modern tools (VS Code's search,
or `ripgrep`/`rg`) do the same thing faster.

---

# CHAPTER 4 — Functions, variables, and the building blocks of code

You don't need to write code to review it, but you must **read** it. Here are the few
building blocks that appear in every language.

**Variable — a named box that holds a value.**
```
let username = "alice"      // a box named username holding the text "alice"
let age = 30                // a box holding the number 30
```

**Function — a named block of instructions you can run by calling its name.**
Think of it as a recipe: give it inputs (**parameters/arguments**), it does steps, and
usually **returns** a result.
```
function addTax(price) {          // "function" defines it; price is the input
    let tax = price * 0.05
    return price + tax            // "return" hands back the answer
}

let total = addTax(100)           // "calling" the function; total becomes 105
```
- `function addTax(price)` — the **definition**.
- `price` — the **parameter** (the input the function expects).
- `return` — what it hands back.
- `addTax(100)` — a **call** (running it with the argument `100`).

**Why functions matter for review.** Security bugs live **inside functions**, and data
flows **from one function into another**. A function that takes user input and passes it to a
database function is the shape of an injection bug. Following that flow is the core skill
(Chapter 11).

**`if` — a decision.**
```
if (user.isAdmin) {
    deleteEverything()      // only runs if the condition is true
}
```
Access-control bugs are often a **missing or wrong `if`** ("it never checks `isAdmin`").

**Class — a bundle of related variables and functions.** (Java and C# are built around these.)
```
class BankAccount {
    balance = 0
    function withdraw(amount) { ... }
}
```
A class is a template; a **method** is just a function that lives inside a class.

**Comment — notes ignored by the computer** (start with `//` or `#`). Developers sometimes
leave secrets or "TODO: add auth check" in comments — worth grepping for.

That's enough to read code. You now know variables, functions, `if`, and classes.

---

# CHAPTER 5 — Source code vs compiled code (and why it matters)

**Source code** is the human-readable text the developer writes (what you review).
**Compiled code** is the machine-number version the computer actually runs.

- **Java** and **C#** are **compiled** — but to an in-between form (**bytecode**), which runs
  on a "virtual machine" (the JVM for Java, the .NET runtime for C#). You review the **source**
  (`.java`, `.cs` files); if you only have the compiled form, you **decompile** it back to
  readable source (like you did for Android APKs).
- **JavaScript** is **interpreted** — the browser/Node runs the source directly, no compile
  step. **TypeScript** is compiled **into JavaScript** before it runs (Chapter 6).

**Why it matters for the assessment.** A code review needs the **source code**. Confirm early
that you've been given the real source (the `src/` folder, `.cs`/`.java`/`.ts` files), not
just a built/minified artifact. If you only get compiled output, you'll need to decompile,
which is slower and loses names/comments.

File extensions tell you the language at a glance:
```
.ts / .tsx   TypeScript        .js / .jsx   JavaScript
.java        Java              .cs          C#
.json .xml .yml   config       .sql         database queries
```

---

# PART 2 — THE LANGUAGES & FRAMEWORKS YOU'LL REVIEW

# CHAPTER 6 — JavaScript and TypeScript (and the difference)

**JavaScript (JS)** is the language of the **web browser**. Originally it only ran in the
frontend to make pages interactive (clicks, menus, form checks). Later, **Node.js** (Chapter
9) let JavaScript also run on the **backend**. So today JavaScript runs on **both** sides.

**What JavaScript is used for:** website frontends (with React/Angular/etc.), and backends
(with Node.js). If you see `.js` files, it could be either side — check where they live.

**TypeScript (TS)** is **JavaScript with types added.** That's the whole idea. A "type" means
you label what kind of value a box holds (text, number, true/false). Plain JavaScript doesn't
force this; TypeScript does.

JavaScript (no types):
```javascript
function addTax(price) {
    return price + price * 0.05
}
```
TypeScript (same thing, with types):
```typescript
function addTax(price: number): number {   // price must be a number; it returns a number
    return price + price * 0.05
}
```
`: number` says "this must be a number." If someone passes text, TypeScript complains
**before the program runs**. This catches mistakes early and makes code easier to read.

**Key facts for review:**
- **TypeScript becomes JavaScript before it runs.** The browser/Node cannot run `.ts`
  directly — a compiler turns it into `.js` first. So TypeScript's safety is only at
  development time; at runtime it's ordinary JavaScript with the same security behavior.
- **Types are not a security control.** `price: number` stops a *programming* mistake, not an
  *attacker*. At runtime, data from the network can still be anything. So don't assume a
  TypeScript app is "validated" just because it has types — **real input validation still has
  to be in the code.**
- You review `.ts`/`.tsx` files the same way you'd review `.js`, looking for the same bugs.

**One-line summary:** *JavaScript runs the web (frontend and, via Node, backend). TypeScript
is JavaScript plus type labels for safer development — it compiles down to JavaScript, and
types are not a security feature.*

---

# CHAPTER 7 — Java (and what it's used for)

**Java** is a **compiled, class-based** language that runs on the **JVM** (Java Virtual
Machine). Its slogan was "write once, run anywhere" — the same compiled Java runs on any
machine that has a JVM.

**What Java is used for:**
- **Backend / server-side applications** — this is the big one for you. Large enterprise and
  banking backends, APIs, and web servers are often Java (commonly with the **Spring** /
  **Spring Boot** framework).
- **Android apps** (the Java/Kotlin side you already studied).
- Big internal systems, payment systems, government systems.

So in this project, **Java code is almost certainly backend** — the server logic, database
access, and APIs. That's where the serious bugs (injection, access control, auth) live.

What Java code looks like:
```java
public class AccountController {
    public String getBalance(String userId) {
        String sql = "SELECT balance FROM accounts WHERE id = " + userId;  // <-- SQLi risk
        return db.query(sql);
    }
}
```
Things to recognize:
- `public class AccountController` — a class (Chapter 4).
- `public String getBalance(...)` — a **method** (a function in a class) that returns text.
- The `sql` line glues user input (`userId`) into a query → classic SQL injection pattern.

**Java frameworks you may see:** **Spring / Spring Boot** (the dominant web framework),
**Jakarta/Java EE**, **Hibernate** (database access). The framework shapes where to look —
e.g. in Spring, request handlers are marked with annotations like `@GetMapping`,
`@PostMapping`, `@RequestMapping` (grep for these to find every entry point).

**Dependency file:** `pom.xml` (Maven) or `build.gradle` (Gradle) — the list of third-party
libraries (what Black Duck scans).

---

# CHAPTER 8 — C#, .NET, and ASP.NET

**C#** (pronounced "C-sharp") is a **compiled, class-based** language made by Microsoft. It is
very similar in style to Java. As you noted: **C# is the main language of the .NET platform
and ASP.NET.** Let's untangle those three names.

- **C#** — the **language** (the words and rules you write).
- **.NET** — the **platform/runtime** that runs C# (the equivalent of Java's JVM, plus a huge
  library of built-in functions). C# compiles to bytecode that .NET runs. (You saw ".NET"
  earlier: the Ajman IdentityServer was a **Duende/.NET** product; the `X-Powered-By: ASP.NET`
  header and the `rundll32`/IIS server were .NET/Windows.)
- **ASP.NET** — the **web framework** built on .NET for making **websites and APIs** in C#.
  "ASP.NET Core" is the modern version. When you see a C# **web** app, it's almost always
  ASP.NET.

So: **you write C#, it runs on .NET, and ASP.NET is how you build web apps/APIs with it.**

**What C# is used for:**
- **Backend web apps and APIs** (ASP.NET) — a major one for you, like Java.
- Windows desktop applications, enterprise systems, games (Unity).

In this project, **C# code is likely backend ASP.NET** — server logic, APIs, database access.

What C# code looks like (note how similar to Java):
```csharp
public class AccountController : ControllerBase
{
    [HttpGet("balance")]                       // this marks a web endpoint (ASP.NET)
    public string GetBalance(string userId)
    {
        var sql = "SELECT balance FROM accounts WHERE id = " + userId;  // <-- SQLi risk
        return _db.Query(sql);
    }
}
```
Things to recognize:
- `[HttpGet("balance")]` — an **attribute** marking a web endpoint. ASP.NET endpoints are
  marked with `[HttpGet]`, `[HttpPost]`, `[Route]`, `[ApiController]` — **grep for these to
  find every entry point.**
- `var` — "figure out the type for me" (like a box without a written label).
- Same SQL-injection pattern as the Java example.

**Dependency file:** `*.csproj` (and `packages.config` in older projects) — the list of
third-party libraries (what Black Duck scans).

**One-line summary:** *C# is the language; .NET is the runtime that executes it; ASP.NET is
the web framework. For you, C# usually means an ASP.NET backend.*

---

# CHAPTER 9 — The frameworks: Node.js, React, Angular, Next.js

A **framework** (or **library**) is **pre-written code that gives you a structure and
ready-made pieces** so you don't build everything from scratch. The language is the raw words;
the framework is a kit built in that language. All four of these are **JavaScript/TypeScript**.

**Node.js — JavaScript on the backend.**
Node is **not** a language; it's a **runtime** that lets JavaScript run on a **server** (not
just in a browser). Before Node, JS was frontend-only. With Node, you can write the **backend**
(APIs, database access, business logic) in JavaScript/TypeScript. The most common backend
framework on Node is **Express**.
- **So:** if you see JS/TS on the **server**, it's running on **Node**. This is backend code —
  look for the serious bugs here.
```javascript
// a Node.js + Express backend endpoint
app.get("/balance", (req, res) => {
    const userId = req.query.userId                 // input from the user
    const sql = "SELECT balance FROM accounts WHERE id = " + userId   // <-- SQLi risk
    db.query(sql).then(rows => res.json(rows))
})
```
Grep for `app.get`, `app.post`, `router.`, `req.query`, `req.body`, `req.params` to find
Node/Express entry points and where user input enters.

**React — a frontend library for building user interfaces.**
React (made by Facebook) builds the **frontend** — the pages and components the user sees. It
is **frontend only**. In React you write pieces called **components**.
- Security angle: React **auto-escapes** text you put on the page, which prevents most XSS.
  But there's a famous dangerous escape hatch: **`dangerouslySetInnerHTML`** — grep for it;
  it puts raw HTML on the page and is a common React XSS sink.
- React files often end in **`.jsx`** or **`.tsx`**.

**Angular — a frontend framework for building user interfaces.**
Angular (made by Google) does the same job as React — builds the **frontend** — but is a
bigger, more complete framework. (You saw Angular on the Ajman HR site: `app-root`,
`_ngcontent`, `ng-version`.) It is **frontend**.
- Security angle: Angular also auto-escapes by default. Its dangerous escape hatch is
  **`bypassSecurityTrust...`** (e.g. `bypassSecurityTrustHtml`) — grep for it; it disables
  Angular's XSS protection.

**Next.js — a framework built on top of React that adds a backend.**
Next.js takes React (frontend) and adds **server-side** abilities: it can render pages on the
server and run backend **API routes**. So a Next.js app is **both frontend and backend** in
one project. This matters for review: in a Next.js codebase, some files run in the browser
(frontend, user-controlled) and some run on the server (backend, trusted) — you must tell them
apart.
- Rough rule: code under `pages/api/` or `app/api/` (API routes) and functions named like
  `getServerSideProps` run on the **server (backend)**; the rest is **frontend**.

**Putting it together:**
```
Node.js   → lets JS run on the server         → BACKEND  (Express)
React     → builds the UI the user sees        → FRONTEND (.jsx/.tsx)
Angular   → builds the UI the user sees        → FRONTEND (bigger framework)
Next.js   → React + a server layer             → BOTH (watch pages/api & server functions)
```

**The review takeaway:** before reading a file, identify **framework → therefore frontend or
backend → therefore which bugs matter.** A missing auth check in backend Node/Express is
critical; a disabled escape in frontend React/Angular is an XSS lead.

---

# PART 3 — SECURE CODE REVIEW ITSELF

# CHAPTER 10 — What secure code review is (and how it differs from pentesting)

**Secure code review** is **reading an application's source code to find security
vulnerabilities**, instead of (or in addition to) attacking the running app from outside.

**Pentest vs code review — the difference, simply:**
- **Pentest (black box):** you're outside the app, poking it with requests, guessing what's
  inside. You see **behavior**, not cause. (What you've done all along.)
- **Code review (white box):** you have the **source code**, so you see the **exact cause** —
  the precise line that builds the SQL query, the missing `if` that should check permissions.
  You can find bugs a pentest would miss (logic flaws, bugs on hard-to-reach paths), and you
  can say exactly how to fix them.

They complement each other. Code review usually finds **more** bugs and explains them
**precisely**, but needs the source and takes reading skill.

**The two ways to do code review:**
1. **Manual** — a human reads the code, follows the data, and reasons about it (Chapter 11).
   Finds logic and access-control bugs tools miss. Slower.
2. **Automated** — tools scan the code and flag suspicious patterns (Chapter 12). Fast and
   wide, but produces **false positives** (flags that aren't real) and **false negatives**
   (misses real bugs, especially logic). Tools like **Black Duck** fit here.

**Best practice: use both.** Run the tools to cover ground fast, then manually review the
important areas (authentication, authorization, input handling, crypto) and triage the tool
findings. A good review is **tool-assisted, human-judged.**

**What "secure" findings look like.** The same OWASP bug classes you know from pentesting —
injection, broken access control, XSS, weak crypto, exposed secrets, vulnerable dependencies —
but spotted as **code patterns** (Chapter 14).

---

# CHAPTER 11 — Manual review: sources, sinks, and data flow (the core skill)

The single most important technique in manual code review is **following untrusted data from
where it enters to where it does something dangerous.** Three words:

- **Source** — where **untrusted input enters** the program (user input). Examples: the body
  or parameters of a web request (`req.query`, `req.body`, `@RequestParam`, `Request.Query`),
  uploaded files, data from another system.
- **Sink** — a **dangerous operation** that is unsafe if fed untrusted data. Examples: a
  database query (SQLi), an OS command (command injection), writing to the page (XSS), a file
  path (path traversal), an HTTP request to a URL you supply (SSRF).
- **Data flow** — the path the data travels **from a source to a sink**. If untrusted data
  reaches a dangerous sink **without being made safe** (validated, parameterized, encoded)
  along the way, you've found a vulnerability.

**The mental model:**
```
SOURCE (user input)  →  ...passes through functions...  →  SINK (dangerous action)
   req.query.id                                               db.query(sql)
                     if nothing sanitizes it in between  =  SQL injection
```

**How to do it in practice:**
1. **Find the entry points (sources).** Grep for the framework's request markers:
   - Node/Express: `req.query`, `req.body`, `req.params`, `app.get`, `app.post`
   - Java/Spring: `@RequestParam`, `@PathVariable`, `@RequestBody`, `@GetMapping`
   - C#/ASP.NET: `[HttpGet]`, `[HttpPost]`, `Request.Query`, `Request.Form`, parameters of
     controller methods
2. **Find the dangerous sinks.** Grep for them (Chapter 14 lists them per language): query
   builders, `exec`/`eval`, HTML output, file paths, URL fetchers, deserializers.
3. **Connect them.** For each sink, trace **backwards**: where does its input come from? If it
   traces back to a source **without proper safety in between**, it's a finding.
4. **Check the "in between" for a safe barrier.** The fix patterns are: **parameterized
   queries** (for SQLi), **output encoding** (for XSS), **allow-lists / validation** (for
   most input), **safe APIs** (e.g. a library that escapes for you). If one of these is
   correctly applied between source and sink, the flow is safe.

**Also review (not everything is a data flow):**
- **Authentication** — how users log in; are passwords hashed (bcrypt/argon2, not MD5); are
  sessions/tokens validated (JWT signature checked, Chapter 14 A07).
- **Authorization / access control** — does every sensitive action check **who** is asking
  and **whether they're allowed** (the missing-`if` bug)? This is the #1 OWASP item and tools
  are bad at it, so it's **mostly manual**.
- **Secrets** — grep for hardcoded passwords/keys/tokens in code and config.
- **Crypto** — weak algorithms (MD5, SHA1, DES), hardcoded keys, static IVs, weak randomness.
- **Configuration** — debug mode on, verbose errors, permissive CORS, missing security
  headers.

**Prioritize.** You rarely have time to read everything. Read, in order: authentication,
authorization, input handling on the most sensitive endpoints (money, admin, personal data),
then crypto and config. Let tools cover the rest.

---

# CHAPTER 12 — Automated tools: SAST, SCA, DAST, secrets scanning

There are four tool categories. Know what each does, because your seniors will name them and
**Black Duck is one specific category (SCA)**.

**1. SAST — Static Application Security Testing.**
Tools that **read the source code** (statically = without running it) and flag vulnerable
**patterns** — the app's **own** code. This is the automated half of code review.
- Finds: injection, XSS sinks, weak crypto, hardcoded secrets, dangerous functions.
- Weakness: **false positives** (flags safe code) and misses **logic/access-control** bugs.
- Tools: **Semgrep** (free, excellent, rule-based), **SonarQube**, **Checkmarx**, **Fortify**,
  CodeQL, Snyk Code.
- Example (Semgrep): `semgrep --config auto .` scans the whole codebase with community rules.

**2. SCA — Software Composition Analysis.**
Tools that look at the app's **third-party libraries** (dependencies) and flag ones with
**known vulnerabilities (CVEs)** or risky **licenses**. This covers **OWASP A06: Vulnerable &
Outdated Components**. **This is what Black Duck is** (Chapter 13).
- Finds: "you use library X version 1.2, which has a known critical CVE — upgrade to 1.5."
- It does **not** find bugs in the app's **own** code — only in the libraries it pulls in.
- Tools: **Black Duck**, **Snyk Open Source**, **OWASP Dependency-Check**, GitHub Dependabot.

**3. DAST — Dynamic Application Security Testing.**
Tools that test the **running** app from the outside (like an automated pentest). Not code
review, but your seniors may mention it. Tools: Burp Scanner, OWASP ZAP, Acunetix.

**4. Secrets scanning.**
Tools that search the code/history for **committed secrets** (API keys, passwords, tokens).
Tools: **gitleaks**, **trufflehog**, GitHub secret scanning.

**How they fit together in one review:**
```
SAST  → bugs in the app's OWN code        (Semgrep, SonarQube)      → you + manual triage
SCA   → bugs in THIRD-PARTY libraries     (Black Duck, Snyk)        → OWASP A06
Secrets → committed keys/passwords         (gitleaks, trufflehog)    → hardcoded secrets
Manual → logic, access control, auth       (your brain + grep)       → the bugs tools miss
```
Run SAST + SCA + secrets scanning to cover ground fast, then **manually review** the critical
areas and **triage every tool finding** (confirm real vs false positive before reporting).

---

# CHAPTER 13 — What is Black Duck?

**Black Duck is an SCA (Software Composition Analysis) tool.** Its job: look at all the
**third-party open-source libraries** your application uses and tell you which ones are
**risky** — either they have **known security vulnerabilities (CVEs)** or they have **license
problems**. (Black Duck is a long-standing commercial product, now under the "Black Duck"
company, formerly part of Synopsys.)

**Why this exists (the problem it solves).** Modern apps are mostly **other people's code**.
A typical app you write yourself might be 10% of the lines; the other 90% are **libraries** it
pulls in (for logging, web handling, JSON, encryption, etc.), and those libraries pull in
*more* libraries (**transitive dependencies**). If any one of those hundreds of libraries has
a known vulnerability, your app has it too. Checking them all by hand is impossible. Black Duck
does it automatically.

**What Black Duck actually does:**
1. **Scans the codebase** and builds a full inventory of every open-source component and its
   **version** (direct and transitive) — a "Bill of Materials" (SBOM).
2. **Matches each component+version against vulnerability databases** (CVEs / the NVD and its
   own research) and **license databases**.
3. **Reports**: "Component `log4j-core 2.14.1` has **CVE-2021-44228 (Log4Shell), Critical** —
   fixed in 2.17.1" and "Component X uses GPL license — legal risk."

**Concrete example.** You already know Log4Shell-type bugs. Black Duck is exactly what finds
them: it reads the `pom.xml`/`package.json`/`*.csproj`, sees the library and version, and
flags the known CVE with a severity and a fixed version — without you knowing every CVE by
heart.

**Where it fits in your review (be clear about its limits):**
- ✅ Black Duck covers **OWASP A06: Vulnerable & Outdated Components** — the "are our
  dependencies safe?" question.
- ❌ Black Duck does **not** find bugs in the app's **own** code (no SQL injection, no broken
  access control, no XSS in the code your team wrote). For those you need **SAST + manual
  review** (Chapters 11–12).
- So in this project: run **Black Duck for dependencies**, and do **SAST + manual review for
  the app's own code**. They cover different halves.

**How you'll likely use it (typical flow):**
1. Point Black Duck at the codebase (it detects the dependency files automatically).
2. It runs a scan and produces a report of components, each with vulnerabilities (by severity)
   and licenses.
3. You **triage**: for each High/Critical, confirm the vulnerable component is actually used
   (not dead code), note the fixed version, and write it up as a finding — "Upgrade library X
   from 1.2 to 1.5 (fixes CVE-YYYY-NNNN, Critical)."

**One-line summary:** *Black Duck is a dependency scanner — it finds known vulnerabilities and
license issues in the third-party libraries your app uses (OWASP A06). It does not review your
team's own code.*

---

# PART 4 — OWASP TOP 10 IN THE CODE

# CHAPTER 14 — OWASP Top 10 (2021), seen in source code

For each of the OWASP Top 10, here is **what the vulnerable code looks like**, **what makes it
safe**, and **what to grep for** — across TypeScript/JS (Node), Java, and C#. This is the heart
of code review: recognizing these patterns.

## A01 — Broken Access Control (the #1 risk; mostly manual)
**What it is.** The code performs a sensitive action **without checking whether the user is
allowed**. Tools miss this; you find it by reading.

Vulnerable (Node): returns any user's data, no check that it's *your* data:
```javascript
app.get("/account/:id", (req, res) => {
    const acc = db.getAccount(req.params.id)   // no check that req.params.id belongs to the caller
    res.json(acc)                               // IDOR — the bug you exploited on Ajman
})
```
Safe: it checks ownership/role before acting:
```javascript
if (acc.ownerId !== req.user.id) return res.status(403).send("forbidden")
```
**What to look for:** endpoints that take an **id** and fetch/modify by it with **no ownership
or role check**; admin functions with no role check; access checks done only in the frontend.
**Grep:** `req.params`, `req.query.id`, `findById`, `@PathVariable`, and then ask "is there an
`if` checking who's allowed?" Look for the **absence** of checks like `isAdmin`, `req.user`,
`@PreAuthorize`, `[Authorize]`.

## A02 — Cryptographic Failures (weak or misused crypto; exposed secrets)
**What it is.** Weak algorithms, hardcoded keys, static IVs, weak randomness, or sensitive
data not encrypted.
Vulnerable (Java): weak hash for passwords:
```java
String hash = MessageDigest.getInstance("MD5").digest(password);  // MD5 — broken
```
Safe: a strong, slow password hash (bcrypt/argon2/PBKDF2).
**Grep (all languages):** `MD5`, `SHA1`, `DES`, `ECB`, `Random()` (for security use),
`IvParameterSpec(new byte[` (static IV), and hardcoded keys: `password =`, `apiKey =`,
`secret =`, `BEGIN PRIVATE KEY`. Check config files (`.env`, `appsettings.json`,
`application.properties`) for secrets too.

## A03 — Injection (SQL, command, and XSS)
**What it is.** Untrusted input is glued into a command/query/page instead of being passed
safely. The classic source→sink bug.

**SQL injection** — vulnerable (string-building):
```csharp
var sql = "SELECT * FROM users WHERE name = '" + name + "'";   // C# — SQLi
db.Query(sql);
```
```java
stmt.executeQuery("SELECT * FROM users WHERE id = " + id);     // Java — SQLi
```
Safe = **parameterized query / prepared statement** (the input is sent separately, never glued
in):
```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, id);                                              // safe
```
**Grep for SQLi:** string concatenation into queries — `"SELECT`, `"INSERT`, `"UPDATE`,
`executeQuery(`, `createQuery(`, `.Query(`, `rawQuery`, `+ userInput`. The red flag is a query
with `+` (gluing) and user input; the safe sign is `?`/`@param` placeholders with
`prepareStatement`/parameterized APIs.

**Command injection** — input passed to the OS shell:
```javascript
exec("ping " + req.query.host)       // Node — command injection
```
**Grep:** `exec(`, `execSync(`, `child_process`, `Runtime.getRuntime().exec` (Java),
`Process.Start`/`ProcessStartInfo` (C#), `os.system`.

**XSS (injection into the page)** — untrusted input written as HTML:
```javascript
element.innerHTML = req.query.name            // DOM XSS
// React:
<div dangerouslySetInnerHTML={{ __html: userInput }} />   // React XSS sink
```
**Grep:** `innerHTML`, `dangerouslySetInnerHTML`, `bypassSecurityTrust` (Angular),
`document.write`, `v-html` (Vue), and server templates that disable auto-escaping (`| raw`,
`@Html.Raw` in C#/Razor, `<%= %>` unescaped).

## A04 — Insecure Design
**What it is.** A flaw in the **design/logic**, not a single bad line — e.g. no rate limiting
on login (allows brute force), a password-reset flow that leaks whether an email exists, a
"confirm order" step that can be skipped. Found by **reasoning about the flow**, not grep.
Look at multi-step flows (auth, payment, reset) and ask "what step can be skipped or abused?"

## A05 — Security Misconfiguration
**What it is.** Insecure settings: debug mode on in production, verbose errors returned to
users, permissive **CORS** (`Access-Control-Allow-Origin: *`), default credentials, missing
security headers, directory listing.
**Grep:** `AllowAnyOrigin`, `Access-Control-Allow-Origin`, `"*"`, `debug = true`,
`DEBUG=True`, `app.UseDeveloperExceptionPage`, `printStackTrace` sent to responses,
`spring.profiles.active=dev`. Check config files closely.

## A06 — Vulnerable & Outdated Components  ← **this is Black Duck's job**
**What it is.** The app uses **third-party libraries with known CVEs** (like Log4Shell).
**How you find it:** this is the one you cover with **SCA / Black Duck** (Chapter 13), not by
reading code. Check the dependency files (`package.json`, `pom.xml`, `*.csproj`) and run the
scanner; report outdated/vulnerable components with their fixed versions.

## A07 — Identification & Authentication Failures
**What it is.** Weak login/session handling: weak password rules, no lockout/rate limit,
predictable or unsigned tokens, **JWT signature not verified**, sessions that don't expire,
credentials in the URL.
Vulnerable (JWT not verified):
```javascript
const data = jwt.decode(token)       // decode does NOT verify the signature — forgeable!
```
Safe:
```javascript
const data = jwt.verify(token, secret)   // verify checks the signature
```
**Grep:** `jwt.decode(` (vs `jwt.verify(`), `alg: "none"`, password comparison with `==`
instead of a constant-time check, missing lockout logic, `MD5`/`SHA1` for passwords, session
timeout settings.

## A08 — Software & Data Integrity Failures (incl. insecure deserialization)
**What it is.** Trusting data/code without checking integrity — the big one in code is
**insecure deserialization** (turning attacker-controlled bytes back into live objects can run
code), and pulling code/updates without verifying them.
**Grep:** `ObjectInputStream`/`readObject` (Java), `BinaryFormatter`/`JavaScriptSerializer`/
`TypeNameHandling` (C#), `pickle`/`yaml.load` (Python), `eval(`, `deserialize(` on untrusted
input.

## A09 — Security Logging & Monitoring Failures
**What it is.** Two sides: **too little** logging (no record of security events, so attacks go
unseen) and **too much / wrong** logging (writing **passwords, tokens, card numbers** into
logs — a leak). Also log injection.
**Grep:** `log.info(... password`, `console.log(... token`, logging of request bodies that may
contain secrets; and conversely, sensitive actions (login, money transfer, admin) with **no**
logging.

## A10 — Server-Side Request Forgery (SSRF)
**What it is.** The server fetches a **URL supplied by the user**, letting an attacker point it
at internal systems or cloud metadata (exactly the Ajman `GetLiveOpenData?url=` bug).
Vulnerable:
```javascript
const data = await fetch(req.query.url)      // SSRF — server fetches attacker's URL
```
**Grep:** `fetch(`, `axios.get(`, `HttpClient`, `WebClient`, `URL(`, `request(`,
`RestTemplate`, `HttpRequestMessage` — with a **user-supplied URL** and no allow-list of
destinations. Safe = validate the URL against an **allow-list** of permitted hosts and block
internal/metadata ranges.

---

# PART 5 — METHODOLOGY & CHECKLIST

# CHAPTER 15 — A repeatable code-review methodology

Follow this order every time so you don't miss things and don't drown in a big codebase.

1. **Understand the app (15 min).** Read the `README`. What does it do? What's sensitive
   (money, PII, admin)? Which languages/frameworks (Chapters 6–9)? Frontend, backend, or both?
2. **Map the codebase.** Find the folders: where are the request handlers (entry points),
   the database access, the auth code, the config files, the dependency files?
3. **Run the automated tools first (they work while you read).**
   - **SCA / Black Duck** on the dependency files → A06 (vulnerable components).
   - **SAST** (Semgrep `--config auto`) on the source → injection/crypto/XSS leads.
   - **Secrets scan** (gitleaks/trufflehog) → hardcoded secrets.
4. **Find all entry points (sources).** Grep the framework's request markers (Chapter 11).
   Make a list — every place user input enters.
5. **Manually review the critical areas, in priority order:**
   - **Authentication** (A07) — login, sessions, tokens, password hashing.
   - **Authorization / access control** (A01) — does every sensitive action check who's
     allowed? (Mostly manual — tools miss this.)
   - **Injection** (A03) — trace each source to its sinks (SQL, command, HTML).
   - **Secrets & crypto** (A02) — hardcoded keys, weak algorithms.
   - **SSRF, deserialization, misconfig** (A10, A08, A05).
6. **Triage every tool finding.** Confirm real vs false positive by reading the actual code.
   Never report a raw tool finding you haven't verified.
7. **Write up findings.** For each: title, severity, the **exact file and line**, the
   vulnerable code, why it's exploitable, and the fix (with a corrected code snippet).

**Time-boxing tip (you're short on time):** if you can't review everything, prioritize the
**backend** code that handles **authentication, authorization, money, and personal data**.
That's where the critical findings almost always are. Let Black Duck/SAST cover the breadth.

---

# CHAPTER 16 — Checklist & grep cheat-sheet

**Entry points (sources) — find where input enters:**
```
Node/Express : req.query  req.body  req.params  app.get  app.post  router.
Java/Spring  : @RequestParam  @PathVariable  @RequestBody  @GetMapping  @PostMapping
C#/ASP.NET   : [HttpGet] [HttpPost] [Route]  Request.Query  Request.Form  (controller params)
```

**Dangerous sinks — find where input could do harm:**
```
SQL injection      : "SELECT …" + input · executeQuery( · createQuery( · .Query( · rawQuery
Command injection  : exec( · execSync( · child_process · Runtime.getRuntime().exec · Process.Start
XSS                : innerHTML · dangerouslySetInnerHTML · bypassSecurityTrust · @Html.Raw · | raw · document.write
Path traversal     : readFile( · File( · Path.Combine · "../" · new FileInputStream(
SSRF               : fetch( · axios · HttpClient · WebClient · RestTemplate · URL(
Deserialization    : readObject · ObjectInputStream · BinaryFormatter · TypeNameHandling · yaml.load · pickle
```

**Crypto & secrets:**
```
Weak crypto : MD5 · SHA1 · DES · ECB · new Random() (security) · static IV
Secrets     : password= · apiKey= · secret= · token= · BEGIN PRIVATE KEY · connectionString
Config files: .env · appsettings.json · application.properties · web.config
```

**Auth & access control (read, don't just grep):**
```
JWT         : jwt.decode( (bad, no verify) vs jwt.verify(  · alg:"none"
AuthZ marks : [Authorize] · @PreAuthorize · req.user · isAdmin  — and note where they're MISSING
Passwords   : bcrypt/argon2/PBKDF2 (good) vs MD5/SHA1/plaintext (bad) · == compare (timing)
```

**Misconfig:**
```
CORS   : AllowAnyOrigin · Access-Control-Allow-Origin: * 
Debug  : debug=true · DEBUG=True · UseDeveloperExceptionPage · printStackTrace to response
```

**Tooling quick commands:**
```
Semgrep (SAST)      : semgrep --config auto .
gitleaks (secrets)  : gitleaks detect --source .
Dependency-Check    : dependency-check --scan .
Black Duck (SCA)    : point it at the repo; it auto-detects package.json / pom.xml / *.csproj
grep (everything)   : grep -rniE "pattern1|pattern2" .
```

**Report each finding as:** title · severity (CVSS) · OWASP category · file:line · vulnerable
snippet · why exploitable · fixed snippet.

---

## References
- OWASP Top 10 — https://owasp.org/Top10/
- OWASP Code Review Guide — https://owasp.org/www-project-code-review-guide/
- OWASP Cheat Sheet Series — https://cheatsheetseries.owasp.org/
- Semgrep (SAST) — https://semgrep.dev/ · rules at https://semgrep.dev/explore
- Black Duck (SCA) — https://www.blackduck.com/
- OWASP Dependency-Check (free SCA) — https://owasp.org/www-project-dependency-check/
- gitleaks — https://github.com/gitleaks/gitleaks · trufflehog — https://github.com/trufflesecurity/trufflehog
