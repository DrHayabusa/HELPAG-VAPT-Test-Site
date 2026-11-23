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
- **Part 3 — Chapters 10–14: Code review itself** — what it is, manual technique
  (sources & sinks), automated tools (SAST/SCA/DAST), **what Black Duck is**, and
  **using Black Duck on a real assignment** (step by step).
- **Part 4 — Chapter 15: OWASP Top 10 in the code** — each item taught in depth: the
  vulnerable code walked through line by line, how to hunt it (grep → trace → confirm),
  the false-positive check, and the fix — across TypeScript, Java, and C#.
- **Part 5 — Chapters 16–18: Methodology, checklist & tool setup** — a repeatable review
  method, a grep cheat-sheet, and installing/running the tools (Semgrep, gitleaks,
  Dependency-Check, Black Duck) from scratch.
- **Appendices A–C** — OWASP↔CWE mapping (for writing findings), a **worked-practice set**
  (10 vulnerable snippets, you find the bug, answers included), and a finding-report template
  plus glossary.

---

# HOW TO STUDY THIS BOOK — plan & flow

**Read this book first, then practice on TryHackMe.** The book is the *map and method*; the
labs are the *reps*. Pair them: read a concept here, then see it live in the matching room.

## A. Learning flow (do once, in order)
```
1. Part 1 (Ch1-5)    Basics: programming language, frontend/backend, codebase, functions
2. Part 2 (Ch6-9)    How to read TypeScript / Java / C# and their frameworks
3. Part 3 (Ch10-14)  What code review is, source -> sink, SAST/SCA, Black Duck
4. Part 4 (Ch15)     OWASP Top 10 IN CODE - every bug, all 3 languages, how to hunt
5. Appendix B        Find-the-bug practice (10 snippets + answers)
6. Ch18 + tools      Install & run Semgrep + Black Duck on any repo
```
Then practice on TryHackMe ("Web Frameworks" path), in this order:
```
7. Code Review room  The method + Semgrep
8. Java room         Spring Boot  (your Java target)
9. .NET room         ASP.NET      (your C# target)
   skip Python & PHP;  cover TypeScript from this book's TS examples (Ch15)
```

## B. The hunting flow (use for EVERY OWASP bug while reading code)
```
1. GREP the sink     the dangerous op (query, command, HTML output, URL fetch, readObject)
2. OPEN the file      read the few lines around it
3. TRACE back         does the input come from the user? (a "source": req param/body/header)
4. CHECK the barrier  is there a safe step? (parameterized query, access-control "if",
                      output encoding, allow-list, signature verify)
5. VERDICT            barrier MISSING = bug (record file:line)  ·  barrier PRESENT = safe
```
This one loop finds all ten — injection, broken authorization, SSRF, deserialization, everything.

## C. On-the-assessment flow (repeat for each codebase)
```
1. Understand the app (README): what it does, what's sensitive, language/framework
2. Run tools (they work while you read): Black Duck (deps) + Semgrep (code) + gitleaks (secrets)
3. Find entry points (sources): grep the framework's request markers (Ch16/17)
4. Manual review, in priority order:
      authentication -> access control -> injection -> crypto/secrets -> SSRF / deserialization / config
5. Apply the hunting flow (B) to each sink
6. Triage every tool finding: open file:line, confirm real vs false positive
7. Write the finding (Appendix C template): title - severity - OWASP/CWE - file:line - fix
```

**One line to remember:** *read the concept here -> see it live in the matching TryHackMe room
-> hunt with the 5-step loop.*

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
but spotted as **code patterns** (Chapter 15).

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
2. **Find the dangerous sinks.** Grep for them (Chapter 15 lists them per language): query
   builders, `exec`/`eval`, HTML output, file paths, URL fetchers, deserializers.
3. **Connect them.** For each sink, trace **backwards**: where does its input come from? If it
   traces back to a source **without proper safety in between**, it's a finding.
4. **Check the "in between" for a safe barrier.** The fix patterns are: **parameterized
   queries** (for SQLi), **output encoding** (for XSS), **allow-lists / validation** (for
   most input), **safe APIs** (e.g. a library that escapes for you). If one of these is
   correctly applied between source and sink, the flow is safe.

**Also review (not everything is a data flow):**
- **Authentication** — how users log in; are passwords hashed (bcrypt/argon2, not MD5); are
  sessions/tokens validated (JWT signature checked, Chapter 15 A07).
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

# CHAPTER 14 — Black Duck on a real assignment (step by step)

Chapter 13 explained *what* Black Duck is (an SCA tool that finds known vulnerabilities in
third-party libraries). This chapter is *how you actually use it* on a real job.

**The two pieces of Black Duck.**
- **Black Duck Hub** — the **server / website** where results live. You log in here to read
  scan results. The client gives you a URL like `https://blackduck.company.com` and an **API
  token** (a long secret string that logs the scanner in instead of a username/password).
- **Black Duck Detect** — the **command-line scanner** you run against the code. It inspects
  the project, works out every third-party component, and uploads the result to the Hub. (It
  used to be called "Synopsys Detect" — same tool.)

**Step 0 — What you need from the client.** Confirm you have: (1) the **source code** (the
repo, *including* the dependency files — `package.json` + `package-lock.json`, `pom.xml`,
`*.csproj`), (2) the **Hub URL**, (3) an **API token**, and (4) written permission/scope to
scan. Ideally also the ability to **build** the project, because Detect is most accurate when
it can resolve dependencies the way a real build does.

**Step 1 — Run Detect against the codebase.** One command downloads and runs it. Representative
example (the client's real URL and token go in the two variables; the exact script URL/version
comes from the client's Black Duck docs):
```
export BLACKDUCK_URL="https://blackduck.company.com"
export BLACKDUCK_API_TOKEN="<token-from-client>"

bash <(curl -s -L https://detect.blackduck.com/detect10.sh) \
  --blackduck.url="$BLACKDUCK_URL" \
  --blackduck.api.token="$BLACKDUCK_API_TOKEN" \
  --detect.source.path="./myapp" \
  --detect.project.name="MyApp" \
  --detect.project.version.name="2026-review"
```
What each part means:
- the `curl … detect10.sh` line downloads and runs the Detect scanner,
- `--detect.source.path` points it at the code folder,
- `--detect.project.name` / `version.name` label this scan in the Hub so you can find it later.

**What Detect does during the scan (two methods):**
1. **Dependency / package-manager scan (accurate).** It reads the manifest + lock files
   (`package-lock.json`, `pom.xml`, `*.csproj`) and asks the package manager for the exact
   component **versions**, including **transitive** ones (libraries pulled in by your
   libraries). This is the reliable match.
2. **Signature scan (broader, noisier).** It also **hashes files** and matches them against
   Black Duck's database of known open-source files, to catch components copied in without a
   package manager. Useful, but produces more false matches — you verify these by hand.

The result is a **BOM** (**Bill of Materials**) — the full list of every open-source component
and version in the app.

**Step 2 — Read the results in the Hub.** Open the project/version you named. You'll see:
- **Components** — every library + version (direct and transitive).
- **Security risk** — each component's known vulnerabilities, shown with a **BDSA** id (Black
  Duck's own advisory id, which maps to a public **CVE**), a **severity** (Critical/High/…), a
  **CVSS score** (a 0–10 number), and a **"solution"** (the fixed version to upgrade to).
- **License risk** — components with risky licenses (e.g. GPL) — a legal concern you report
  separately.
- **Operational risk** — very old / unmaintained components.

**Step 3 — Triage (the real skill — never dump the raw list).** For each **High/Critical**:
1. **Direct or transitive?** Direct (your team chose it) is easy to fix; transitive means it
   came via another library — note the chain so they know what to upgrade.
2. **Is there a fixed version?** The Hub shows it → "Upgrade X 1.2 → 1.5."
3. **Is the vulnerable part actually used/reachable?** Black Duck flags a component's CVE
   whether or not your app calls the vulnerable function. If time allows, check in the code
   whether the risky feature is used — it strengthens the finding and cuts false alarms.
4. **Set status in the Hub:** mark each as Needs Review, Remediated, or **Ignored / False
   Positive** with a note (e.g. a dev-only/test dependency that never ships to production).

**Step 4 — Write the findings.** Group by severity. Each one:
> *Component `log4j-core 2.14.1` has **CVE-2021-44228 (Log4Shell)** — Critical, CVSS 10.0,
> remote code execution. Fixed in **2.17.1**. Pulled in transitively via
> `spring-boot-starter-log4j2`. Recommendation: upgrade to 2.17.1+.*

**Worked example (Log4Shell).** You give Detect the repo. It reads `pom.xml`, resolves the full
dependency tree, and sees `log4j-core 2.14.1` — even though your team never wrote
`import log4j` directly, it came in **transitively**. The Hub flags CVE-2021-44228, Critical,
fix 2.17.1. You confirm the app logs user-controlled data, mark it Critical, and write the
upgrade recommendation. That's the whole loop.

**Remember Black Duck's boundary.** It covers **only third-party components (OWASP A06)**. It
will **not** find the SQL injection, broken access control, or XSS your team wrote — those are
the next chapter (manual review + SAST). On a real assignment you run **both**: Black Duck for
the dependencies, and the OWASP code review below for the app's own code.

---

# PART 4 — OWASP TOP 10 IN THE CODE

# CHAPTER 15 — OWASP Top 10 (2021) in source code: reading and finding each one

This is the core of code review. **Yes — code review uses the same OWASP Top 10 you know from
pentesting**; you just find each one by **reading the code** instead of attacking a running app.

For every item below you get the same four things, so you can actually *do* it:
1. **What it is** — plain definition, every term explained.
2. **What the vulnerable code looks like** — a real snippet, walked through line by line.
3. **How to hunt it** — the exact search, then how to **trace** and **confirm** it's real.
4. **The fix** — the corrected code, so you can write the remediation.

**The universal hunting loop (use it for every item):**
```
1. GREP for the sink   → find the dangerous operation (a query, a command, HTML output, a fetch)
2. OPEN the file       → read the few lines around it
3. TRACE backwards     → where does its input come from? follow it to a "source" (= user input)
4. CHECK the barrier   → is there a safe step in between? (parameterized query, output encoding,
                         an access-control "if", input validation)   Present = safe. Absent = BUG.
5. VERDICT             → real finding (record file:line) OR false positive (a correct barrier exists)
```
Keep this loop in your head through all ten. "Source" and "sink" are from Chapter 11.

## A01 — Broken Access Control (the #1 risk — and mostly invisible to tools)
**What it is.** **Access control** = the rules deciding **who is allowed to do what**. Broken
access control = the code does a sensitive action **without properly checking the logged-in
user is allowed** to. Two flavors you'll meet most:
- **IDOR** (Insecure Direct Object Reference) — the code fetches a record by an **id** from the
  request without checking the record **belongs to** that user (you exploited exactly this on
  Ajman: change the reference number → get someone else's record).
- **Missing role check** — an admin-only action that never checks "is this user an admin?"

**Vulnerable code (Node), walked through:**
```javascript
app.get("/account/:id", (req, res) => {          // endpoint: /account/<id>
    const acc = db.getAccount(req.params.id)      // (1) takes id straight from the URL
    res.json(acc)                                 // (2) returns the account — NO ownership check
})
```
- Line (1): `req.params.id` is the **source** — the user fully controls it (they can put any
  number).
- Line (2): it returns whatever account matches and **never checks** the account belongs to the
  caller. So user 5 can read `/account/6`. That is IDOR.

**How to hunt it:**
1. **Grep for lookups by id / entry points:** `req.params`, `req.query.id`, `findById`,
   `getById`, `@PathVariable`, `[FromRoute]`.
2. **Open each and ask the key question:** *"After it gets the id, is there an `if` that checks
   the current user is allowed?"* — an ownership check (`acc.ownerId === req.user.id`) or a role
   check (`if (req.user.isAdmin)`, `@PreAuthorize`, `[Authorize]`).
3. **The bug is the ABSENCE of that check.** Unlike injection, you hunt for something
   **missing** — that's why tools miss it and you must read.
4. **Confirm:** trace whether the logged-in identity (`req.user`) is ever compared to the
   object's owner/role. If not → real finding.

**False-positive check:** the guard may live in **middleware** (a function that runs before the
handler) or an **annotation/attribute** (`[Authorize(Roles="Admin")]`, `@PreAuthorize`). Before
reporting, confirm no such guard wraps the route. If a correct one exists, it's safe.

**Fix:**
```javascript
const acc = db.getAccount(req.params.id)
if (acc.ownerId !== req.user.id) return res.status(403).send("forbidden")   // ownership check
res.json(acc)
```

**More real examples — Java (Spring) and C# (ASP.NET):**

Vulnerable (Java / Spring — IDOR, no ownership check):
```java
@GetMapping("/invoices/{id}")
public Invoice getInvoice(@PathVariable Long id) {
    return invoiceRepository.findById(id).orElseThrow();   // never checks the invoice is the caller's
}
```
Fixed (Java / Spring — compare the record's owner to the logged-in user):
```java
@GetMapping("/invoices/{id}")
public Invoice getInvoice(@PathVariable Long id, @AuthenticationPrincipal User user) {
    Invoice inv = invoiceRepository.findById(id).orElseThrow();
    if (!inv.getOwnerId().equals(user.getId()))           // ownership check
        throw new AccessDeniedException("forbidden");
    return inv;
}
```
Vulnerable (C# / ASP.NET — admin action with no role check):
```csharp
[HttpDelete("users/{id}")]
public IActionResult DeleteUser(int id) {                 // anyone logged in can delete any user
    _users.Delete(id);
    return Ok();
}
```
Fixed (C# / ASP.NET — require the Admin role):
```csharp
[Authorize(Roles = "Admin")]                              // only admins reach this
[HttpDelete("users/{id}")]
public IActionResult DeleteUser(int id) {
    _users.Delete(id);
    return Ok();
}
```

## A02 — Cryptographic Failures (weak crypto and exposed secrets)
**What it is.** "Cryptography" = protecting data with math. A cryptographic failure = using it
**wrongly or weakly**. Terms you need:
- **Hash** — a one-way fingerprint of data (used for passwords). A **strong** password hash is
  deliberately **slow** (bcrypt, argon2, PBKDF2). **MD5/SHA1 are fast and broken** for
  passwords.
- **Encryption** — reversible scrambling with a **key**. An **IV** (initialization vector) is a
  value that must be **random each time**; a fixed IV leaks patterns. **ECB** is a weak
  encryption mode that also leaks patterns.

**Vulnerable (Java), walked through:**
```java
String hash = toHex(MessageDigest.getInstance("MD5").digest(password.getBytes()));
```
- `getInstance("MD5")` selects **MD5** — fast and broken. Passwords hashed with MD5 can be
  cracked in bulk. That's a finding on its own.

**How to hunt it:**
1. **Grep for weak algorithms:** `MD5`, `SHA1`, `SHA-1`, `DES`, `RC4`, `ECB`, `Math.random`/
   `new Random()` used for tokens, `IvParameterSpec(new byte[` (a fixed all-zero IV).
2. **Grep for hardcoded secrets:** `password =`, `apiKey =`, `secret =`, `private key`,
   `BEGIN RSA PRIVATE KEY`, `connectionString`, and scan **config files** (`.env`,
   `appsettings.json`, `application.properties`, `web.config`).
3. **Confirm the context:** MD5 protecting a **password/token/signature** = finding.

**False-positive check:** weak hashes are sometimes used for harmless things (cache keys,
ETags, file-change checks). Only flag when it protects something security-relevant.

**Fix:**
```java
String hash = BCrypt.hashpw(password, BCrypt.gensalt());   // bcrypt — slow, salted
```
and move secrets out of code into environment variables / a secrets manager.

**More real examples — C# and a hardcoded secret in config:**

Vulnerable (C# — weak hash + encryption key hardcoded in the source):
```csharp
var md5  = MD5.Create();                                   // broken algorithm
var hash = Convert.ToHexString(md5.ComputeHash(Encoding.UTF8.GetBytes(password)));
var key  = "A1b2C3d4E5f6G7h8";                             // hardcoded encryption key
```
Vulnerable (config file — a password committed into source control):
```json
// appsettings.json
{ "ConnectionStrings": { "Db": "Server=db;User=sa;Password=P@ssw0rd123;" } }
```
Fixed (C# — strong hash + secret pulled from configuration/environment, never from code):
```csharp
var hash = BCrypt.Net.BCrypt.HashPassword(password);       // slow, salted
var key  = config["Encryption:Key"];                       // loaded from env / a secrets vault
```

## A03 — Injection: SQL, Command, and XSS (the classic source → sink bug)
**What it is.** **Injection** = untrusted input is **glued into** a query/command/page as if it
were trusted code, so the attacker's input changes the meaning. This is the purest
**source → sink** bug (Chapter 11): user input (**source**) reaches a dangerous operation
(**sink**) with no safe step between.

### SQL injection
**Vulnerable (C#), walked through:**
```csharp
var name = Request.Query["name"];                               // (1) source: user input
var sql  = "SELECT * FROM users WHERE name = '" + name + "'";   // (2) glued into the query
db.Query(sql);                                                  // (3) sink: runs the query
```
- (1) `Request.Query["name"]` is user-controlled.
- (2) `+ name +` **concatenates** (glues) it into SQL text. If `name` is `' OR '1'='1`, the
  logic changes — injection.
- (3) the database runs the attacker-shaped query.

**How to hunt SQLi:**
1. **Grep for query sinks:** `"SELECT`, `"INSERT`, `"UPDATE`, `"DELETE`, `executeQuery(`,
   `createQuery(`, `.Query(`, `rawQuery(`, `FromSqlRaw(`, `createStatement(`.
2. **Open each and look for GLUING:** a `+`, or string interpolation (`$"...{name}..."` in C#,
   `` `...${name}...` `` in JS, `String.format`/concatenation in Java) that drops a variable into
   the query string.
3. **Trace the variable back:** does it come from a **source** (request param/body)? Glued +
   user-sourced → SQLi.
4. **Confirm the barrier is missing:** the safe sign is **placeholders** — `?` or named params
   (`@name`, `:id`) with `prepareStatement`/parameterized APIs, or an **ORM** used normally.

**False-positive check:** parameterized queries and ORMs (Entity Framework, Hibernate,
Sequelize) are safe — **unless** code builds raw SQL strings inside them
(`createQuery("... " + input)`, `.rawQuery`, `FromSqlRaw($"...{input}")`).

**Fix (parameterized):**
```csharp
db.Query("SELECT * FROM users WHERE name = @name", new { name });   // input sent separately
```
**More real examples — Java and TypeScript:**

Vulnerable (Java — concatenated SQL):
```java
String id = request.getParameter("id");                             // source
Statement st = conn.createStatement();
ResultSet rs = st.executeQuery("SELECT * FROM accounts WHERE id = " + id);   // glued → SQLi
```
Fixed (Java — prepared statement with a `?` placeholder):
```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM accounts WHERE id = ?");
ps.setInt(1, Integer.parseInt(id));                                 // input sent separately
ResultSet rs = ps.executeQuery();
```
Vulnerable → Fixed (TypeScript / Node):
```typescript
db.query(`SELECT * FROM users WHERE email = '${req.body.email}'`);  // glued → SQLi
db.query("SELECT * FROM users WHERE email = $1", [req.body.email]);  // fixed: placeholder
```

### Command injection
**What it is.** User input reaches a call that runs an **operating-system command**, so the
attacker can run their own commands.
```javascript
exec("ping -c 1 " + req.query.host)        // host = "x; rm -rf /"  → runs rm
```
**Hunt:** grep `exec(`, `execSync(`, `spawn(` with a shell, `child_process` (Node),
`Runtime.getRuntime().exec`, `ProcessBuilder` (Java), `Process.Start`, `ProcessStartInfo`
(C#), `os.system`. Trace the argument to a source. **Safe sign:** a fixed command with
arguments passed as an **array** (no shell string-building), or no user input in the command.

Vulnerable → Fixed (Java — pass the argument separately, no shell):
```java
Runtime.getRuntime().exec("nslookup " + host);     // vulnerable: host glued into a command line
new ProcessBuilder("nslookup", host).start();      // fixed: host is a separate argument
```
Vulnerable → Fixed (C# — no shell, arguments as a list):
```csharp
Process.Start("cmd.exe", "/c ping " + host);                        // vulnerable (shell)
Process.Start(new ProcessStartInfo("ping") { ArgumentList = { "-n", "1", host } });  // fixed
```

### XSS (injection into the web page)
**What it is.** Untrusted input is written into the page as **HTML/markup**, so the attacker's
`<script>` runs in the victim's browser. (The XSS you test in pentests — here you spot the
**sink** in code.)
```javascript
element.innerHTML = location.hash                         // DOM XSS: writes raw HTML
<div dangerouslySetInnerHTML={{ __html: userInput }} />   // React's raw-HTML escape hatch
```
**Hunt:** grep `innerHTML`, `outerHTML`, `document.write`, `dangerouslySetInnerHTML` (React),
`bypassSecurityTrustHtml` (Angular), `v-html` (Vue), `@Html.Raw` (C#/Razor), `| safe`/`| raw`
(templates), unescaped `<%= %>`. **Safe sign:** frameworks **auto-escape** normal output
(`{{ value }}` in Angular/Vue, `{value}` in React) — the bug is where that escaping is
**bypassed** by a sink above, and the value traces to user input.
**Fix:** don't build HTML from input; let the framework escape it, or sanitize with DOMPurify
if raw HTML is truly required.

Vulnerable → Fixed (C# / Razor and Angular):
```csharp
@Html.Raw(Model.Comment)    <!-- C#/Razor — vulnerable: writes raw HTML -->
@Model.Comment              <!-- fixed: Razor auto-encodes the value -->
```
```typescript
// Angular — vulnerable: turns OFF Angular's sanitizer
this.safeHtml = this.sanitizer.bypassSecurityTrustHtml(userInput);
// fixed: bind as text and Angular escapes it
// template:  <div>{{ userInput }}</div>
```

## A04 — Insecure Design
**What it is.** A weakness in the **logic/flow** of a feature, not a single bad line — the
design itself is unsafe. Examples: **no rate limiting** on login (brute force works), a
**password-reset** that reveals whether an email exists (user enumeration), a checkout that
lets you **skip the payment step**, a coupon that can be applied unlimited times.
**How to hunt it:** you can't grep a design flaw — you **reason about multi-step flows**. Find
the sensitive flows (login, registration, password reset, payment, money transfer) and for each
ask: *"What step can be skipped, repeated, or done out of order? What control is missing — a
limit, a check, a confirmation?"* Concrete checks: is there a **lockout/throttle** on login?
Does password reset behave **identically** whether or not the email exists? Can a request be
**replayed**?
**Fix:** add the missing control to the design — rate limits, generic responses, server-side
state that enforces step order.

## A05 — Security Misconfiguration
**What it is.** The app is configured insecurely: **debug mode** on in production (leaks stack
traces), verbose errors sent to users, **permissive CORS**, default credentials, missing
security headers, directory listing enabled. (**CORS** = the browser rule for which *other*
sites may call this API; `Access-Control-Allow-Origin: *` means **everyone**.)
**Vulnerable (C#):**
```csharp
app.UseCors(p => p.AllowAnyOrigin().AllowAnyHeader());   // any website can call this API
app.UseDeveloperExceptionPage();                         // shows stack traces to users
```
**How to hunt it:** grep `AllowAnyOrigin`, `Access-Control-Allow-Origin`, `"*"`,
`UseDeveloperExceptionPage`, `debug = true`, `DEBUG=True`, `printStackTrace` sent in responses,
`spring.profiles.active=dev`, `ASPNETCORE_ENVIRONMENT=Development`. Read **config files**
closely (`appsettings.json`, `web.config`, `application.properties`, `.env`).
**False-positive check:** confirm the setting applies to **production**, not only a local-dev
profile (the main false positive here).
**Fix:** restrict CORS to known origins, disable debug/verbose errors in production, add
security headers, remove defaults.

Vulnerable → Fixed (Java / Spring and a config file):
```java
@CrossOrigin(origins = "*")                        // vulnerable: any website can call this API
@CrossOrigin(origins = "https://app.company.com")  // fixed: only the trusted origin
```
```properties
# application.properties
server.error.include-stacktrace=always   # vulnerable: full stack traces to users
spring.profiles.active=dev               # vulnerable: dev profile in production
server.error.include-stacktrace=never    # fixed
```

## A06 — Vulnerable & Outdated Components  ← **this is Black Duck's job**
**What it is.** The app uses **third-party libraries with known vulnerabilities (CVEs)** — like
Log4Shell. The bug isn't in your team's code; it's in a library they pulled in (often
**transitively** — a library of a library).
**How you find it:** this is the one you cover with **SCA / Black Duck** (Chapters 13–14), not
by reading source. Check the dependency files (`package.json` + lockfile, `pom.xml`, `*.csproj`),
run the scanner, and report each outdated/vulnerable component with its **fixed version**.
Manual backup if no scanner: list the dependencies and check each version against public CVE
databases (NVD) or GitHub Advisories.
**Fix:** upgrade to the patched version; remove unused dependencies.

## A07 — Identification & Authentication Failures
**What it is.** Weaknesses in **how users prove who they are** (login) and how sessions/tokens
are handled: weak password rules, **no lockout/rate limit** (brute force), predictable or
**unverified tokens**, sessions that never expire, credentials in the URL. A key code bug:
**not verifying a JWT's signature.** (A **JWT** = a signed token the server gives a logged-in
user; the signature proves the server made it. If you only **decode** it without **verifying**,
anyone can forge one.)
**Vulnerable (Node), walked through:**
```javascript
const data = jwt.decode(token)      // decode ONLY reads the token — it does NOT check the signature
if (data.role === "admin") { ... }  // trusting a forgeable value
```
- `jwt.decode` reads the token's contents **without checking the signature**, so an attacker
  can craft a token saying `role: admin`. The correct call is `jwt.verify`.
**How to hunt it:** grep `jwt.decode(` (the bug) vs `jwt.verify(` (the fix), `alg: "none"`
(disables signature checks), `verify: false`, password comparison with `==`/`.equals` (should
be constant-time), missing lockout/throttle on login, `MD5`/`SHA1` for passwords (ties to A02),
long or absent session timeouts. **Confirm:** trace whether every protected route actually
**verifies** the token and checks expiry.
**Fix:** `jwt.verify(token, secret)`; enforce strong passwords, lockout, and short-lived tokens.

**More real examples — Java and C#:**
```java
// Java (jjwt) — vulnerable: parses the token without a signing key (no signature check)
Jwts.parserBuilder().build().parse(token);
// fixed: verify the signature with the key, and reject anything unsigned/tampered
Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
```
```csharp
// C# / ASP.NET — vulnerable: signature validation disabled
new JwtSecurityTokenHandler().ValidateToken(token, new TokenValidationParameters {
    ValidateIssuerSigningKey = false,
    SignatureValidator = (t, p) => new JwtSecurityToken(t)   // accepts ANY token
}, out _);
// fixed: validate the signing key and the token lifetime
new TokenValidationParameters {
    ValidateIssuerSigningKey = true, IssuerSigningKey = key, ValidateLifetime = true };
```
Password check — vulnerable `if (input == storedHash)` (and MD5 storage) → fixed:
```csharp
if (BCrypt.Net.BCrypt.Verify(input, storedHash)) { /* login ok */ }   // slow, constant-time
```

## A08 — Software & Data Integrity Failures (incl. insecure deserialization)
**What it is.** Trusting data or code **without checking it hasn't been tampered with**. The
headline code bug is **insecure deserialization**: "serialization" turns an object into bytes to
store/send; "deserialization" turns bytes back into a live object. If those bytes are
**attacker-controlled**, deserializing them can **create dangerous objects and even run code**.
Also includes pulling updates/libraries without verifying their signature.
**Vulnerable (Java):**
```java
ObjectInputStream in = new ObjectInputStream(request.getInputStream());
Object obj = in.readObject();      // deserializing attacker bytes → possible remote code execution
```
**How to hunt it:** grep `readObject`, `ObjectInputStream` (Java), `BinaryFormatter`,
`JavaScriptSerializer`, `TypeNameHandling` = Auto/All (C#/JSON.NET), `yaml.load` (unsafe),
`pickle.loads` (Python), `eval(`, and any `deserialize(` fed from a request. **Confirm** the
input is untrusted (from the network/user). **Fix:** avoid deserializing untrusted data; use
safe formats (plain JSON into known types); verify signatures on updates.

**More real examples — C#:**
```csharp
// vulnerable: BinaryFormatter on attacker-controlled bytes — can run code (RCE)
var obj = new BinaryFormatter().Deserialize(request.Body);
// vulnerable: JSON.NET with type info enabled → object injection
JsonConvert.DeserializeObject(json,
    new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All });   // DANGEROUS
// fixed: deserialize into a known, fixed type with no type-name handling
OrderDto dto = JsonConvert.DeserializeObject<OrderDto>(json);
```

## A09 — Security Logging & Monitoring Failures
**What it is.** Two opposite problems: (a) **too little** — sensitive actions (login, money
transfer, admin changes) aren't logged, so attacks go unnoticed; and (b) **too much / wrong** —
logging **secrets** (passwords, tokens, card numbers), which leaks them into log files.
**Vulnerable:**
```javascript
console.log("login attempt", { user, password })   // writes the PASSWORD into the logs
```
**How to hunt it:** grep log calls near secrets — `log.info`, `logger.`, `console.log`,
`Console.WriteLine` — on the same line as `password`, `token`, `secret`, `card`, `cvv`, or
logging whole request bodies. Conversely, check that sensitive endpoints **do** record an audit
event. **Fix:** never log secrets (mask them); log security events (who did what, when).

## A10 — Server-Side Request Forgery (SSRF)
**What it is.** The **server** makes an HTTP request to a **URL the user supplies**, letting an
attacker point it at **internal** systems or the cloud **metadata** service (you found exactly
this on Ajman: `GetLiveOpenData?url=http://localhost/` returned the internal page).
**Vulnerable (Node), walked through:**
```javascript
const url  = req.query.url                 // (1) source: user supplies the URL
const data = await fetch(url)              // (2) sink: server fetches whatever they asked for
res.send(await data.text())                // (3) returns the internal response to the attacker
```
**How to hunt it:** grep the HTTP-client sinks — `fetch(`, `axios`, `request(`, `http.get`
(Node), `HttpClient`, `WebClient`, `RestTemplate`, `URL(...).openConnection` (Java/C#) — and
check whether the **URL/host comes from user input**. **Confirm** there's no **allow-list** of
permitted destinations. **Fix:** validate the URL against an **allow-list** of exact hosts,
block private/loopback/metadata IP ranges, and don't return the raw fetched body.

**More real examples — Java and C#:**
```java
// Java — vulnerable: server fetches a user-supplied URL
String url  = request.getParameter("url");
String body = new RestTemplate().getForObject(url, String.class);   // SSRF
// fixed: allow-list the host before fetching
URI u = URI.create(url);
if (!Set.of("api.partner.com").contains(u.getHost())) throw new BadRequestException();
```
```csharp
// C# — vulnerable
var body = await new HttpClient().GetStringAsync(Request.Query["url"]);   // SSRF
// fixed: validate against an allow-list of exact hosts
var uri = new Uri(Request.Query["url"]);
if (uri.Host != "api.partner.com") return BadRequest();
```

---

# PART 5 — METHODOLOGY & CHECKLIST

# CHAPTER 16 — A repeatable code-review methodology

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

# CHAPTER 17 — Checklist & grep cheat-sheet

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

# CHAPTER 18 — Setting up your tools (installation → first scan)

You'll run automated tools alongside manual review. Here's how to install and run each one
**from zero**, so nothing is new on the day of the assessment. You need a terminal and, ideally,
**VS Code** to read the code.

**0. Get the code into a readable place.**
```
git clone <repo-url> myapp      # or unzip the source the client gave you
cd myapp
code .                          # open the folder in VS Code (Ctrl/Cmd+Shift+F = search everything)
```
VS Code's search (the magnifying glass) is `grep` with a UI — use it for the hunting loop.

**1. Semgrep (SAST — bugs in the app's own code).** Free, fast, rule-based.
```
pip install semgrep             # or:  brew install semgrep   (macOS)
semgrep --config auto .                         # community rules for the detected languages
semgrep --config "p/owasp-top-ten" .            # just OWASP-focused rules
semgrep --config auto --sarif -o semgrep.sarif .# machine-readable report to triage
```
Open each finding at its file:line and apply the Chapter 15 confirm step (real vs false positive).

**2. gitleaks / trufflehog (secrets — committed keys & passwords).**
```
brew install gitleaks           # or download the binary from the GitHub releases page
gitleaks detect --source . --report-path gitleaks.json
pip install trufflehog  ||  docker run -v "$PWD:/x" trufflesecurity/trufflehog filesystem /x
```
These find hardcoded secrets (A02) — verify each is a **real** secret, not a dummy/test value.

**3. OWASP Dependency-Check (free SCA — a free stand-in for Black Duck).**
```
# download the CLI from the OWASP Dependency-Check project, then:
dependency-check --scan ./myapp --format HTML --out dc-report
# open dc-report/dependency-check-report.html
```
Lists third-party components with known CVEs — same job as Black Duck, free and less thorough.
Good when the client doesn't have Black Duck for a given repo.

**4. Black Duck Detect (the client's SCA — full workflow in Chapter 14).**
You don't really "install" it — the one-liner downloads and runs it, using the client's Hub URL
and token:
```
export BLACKDUCK_URL="https://blackduck.company.com"
export BLACKDUCK_API_TOKEN="<token-from-client>"
bash <(curl -s -L https://detect.blackduck.com/detect10.sh) \
  --blackduck.url="$BLACKDUCK_URL" --blackduck.api.token="$BLACKDUCK_API_TOKEN" \
  --detect.source.path="./myapp" --detect.project.name="MyApp" \
  --detect.project.version.name="2026-review"
```
Then read and triage the results in the Hub (Chapter 14).

**5. Language-specific quick scanners (optional, handy):**
```
npm audit                          # Node/JS dependencies — quick known-CVE check
dotnet list package --vulnerable   # .NET/C# dependencies
mvn dependency-check:check         # Java/Maven (OWASP Dependency-Check plugin)
```

**The order on a real job:** clone → open in VS Code → run **Black Duck (or Dependency-Check)**
+ **Semgrep** + **gitleaks** (they work while you read) → start the **manual** review (auth,
access control) → then **triage every tool finding**. Never report a raw tool hit you haven't
opened and confirmed.

---

# APPENDIX A — OWASP Top 10 (2021) ↔ CWE mapping (for writing findings)

Cite the specific **CWE** in each finding — it's more precise than the OWASP category.

| OWASP (2021) | Common CWEs to cite |
|---|---|
| A01 Broken Access Control | CWE-284 (Improper Access Control), CWE-639 (IDOR), CWE-862 (Missing Authorization) |
| A02 Cryptographic Failures | CWE-327 (Weak Crypto), CWE-328 (Weak Hash), CWE-798 (Hardcoded Credentials), CWE-319 (Cleartext Transmission) |
| A03 Injection | CWE-89 (SQL Injection), CWE-79 (XSS), CWE-78 (OS Command Injection), CWE-77 |
| A04 Insecure Design | CWE-209 (Info in Error Message), CWE-840 (Business-Logic Error), CWE-307 (No Lockout) |
| A05 Security Misconfiguration | CWE-16, CWE-942 (Permissive CORS), CWE-756, CWE-614 |
| A06 Vulnerable & Outdated Components | CWE-1104 (Unmaintained Component), CWE-937 |
| A07 Identification & Auth Failures | CWE-287 (Improper Authentication), CWE-384 (Session Fixation), CWE-295 (Improper Cert Validation), CWE-347 (Improper Signature Verification — JWT) |
| A08 Software & Data Integrity Failures | CWE-502 (Insecure Deserialization), CWE-345, CWE-494 |
| A09 Logging & Monitoring Failures | CWE-778 (Insufficient Logging), CWE-532 (Secrets in Logs) |
| A10 SSRF | CWE-918 (SSRF) |

The **CWE Top 25** (MITRE's most-dangerous list) is mostly these same CWEs — e.g. CWE-79, CWE-89,
CWE-78, CWE-287, CWE-502, CWE-918, plus CWE-22 (Path Traversal), CWE-352 (CSRF), CWE-434
(Unrestricted File Upload), CWE-20 (Improper Input Validation). If you can name the exact CWE in
a finding, do — it reads as precise and the client can look it up.

---

# APPENDIX B — Worked practice: find the bug (answers at the end)

Read each snippet, decide **which OWASP item + CWE it is and why**, then check the answers. Treat
every value from a request/param/body/header as attacker-controlled.

**B1 (C#)**
```csharp
[HttpGet("report/{id}")]
public IActionResult GetReport(int id) {
    var r = _db.Reports.Find(id);
    return File(r.Bytes, "application/pdf");
}
```
**B2 (Java)**
```java
String q = "SELECT * FROM users WHERE email = '" + email + "' AND pass = '" + pass + "'";
rs = stmt.executeQuery(q);
```
**B3 (TypeScript / Node)**
```typescript
app.get("/fetch", async (req, res) => {
  const r = await fetch(req.query.target as string);
  res.send(await r.text());
});
```
**B4 (C#)**
```csharp
var token = Request.Headers["Authorization"];
var jwt = new JwtSecurityToken(token);            // read the claims
if (jwt.Claims.First(c => c.Type == "role").Value == "admin") { /* allow */ }
```
**B5 (Java / Spring)**
```java
@PostMapping("/avatar")
public void upload(@RequestParam String filename, @RequestParam byte[] data) throws IOException {
    Files.write(Paths.get("/var/www/uploads/" + filename), data);
}
```
**B6 (TypeScript / React)**
```tsx
function Comment({ text }: { text: string }) {
  return <div dangerouslySetInnerHTML={{ __html: text }} />;
}
```
**B7 (C#)**
```csharp
var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
_db.Save(new User { Email = email, PasswordHash = hash });
```
**B8 (Java)**
```java
String cmd = "convert " + request.getParameter("file") + " out.png";
Runtime.getRuntime().exec(cmd);
```
**B9 (Node / config)**
```javascript
app.use(cors({ origin: "*", credentials: true }));
```
**B10 (Java)**
```java
ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
Session s = (Session) ois.readObject();
```

**Answers**
- **B1 — Broken Access Control / IDOR (A01, CWE-639).** `id` comes from the URL and it never
  checks the report belongs to the caller. Fix: verify ownership before returning.
- **B2 — SQL Injection (A03, CWE-89).** Email and password are glued into the query. Fix:
  parameterized query. (Bonus: passwords compared in plaintext — also A02.)
- **B3 — SSRF (A10, CWE-918).** The server fetches a user-supplied URL. Fix: allow-list hosts,
  block internal ranges.
- **B4 — Authentication failure (A07, CWE-347).** `new JwtSecurityToken(token)` only **reads**
  the token — it never **verifies the signature** — so the `admin` role is forgeable. Fix:
  validate signature + lifetime.
- **B5 — Path Traversal + Unrestricted Upload (A01/A03, CWE-22 / CWE-434).** `filename` is
  attacker-controlled; `../../` escapes the uploads folder. Fix: validate the name, store under a
  generated name.
- **B6 — XSS (A03, CWE-79).** `dangerouslySetInnerHTML` writes untrusted `text` as raw HTML. Fix:
  render as text (`{text}`) or sanitize with DOMPurify.
- **B7 — Cryptographic Failure (A02, CWE-328).** SHA-1 (fast, unsalted) for passwords. Fix:
  bcrypt/argon2.
- **B8 — OS Command Injection (A03, CWE-78).** `file` is glued into a shell command. Fix: pass
  args as a list via ProcessBuilder, no shell.
- **B9 — Security Misconfiguration (A05, CWE-942).** `origin:"*"` **with** `credentials:true` is
  especially dangerous (browsers forbid it) — any site, with cookies. Fix: list exact origins.
- **B10 — Insecure Deserialization (A08, CWE-502).** `readObject()` on network bytes can run
  code. Fix: don't deserialize untrusted data; use a safe format.

If you can name the OWASP category **and** the CWE for each, you're ready to triage real findings.

---

# APPENDIX C — Finding report template + glossary

**Write every finding like this:**
```
Title:        <short, specific>   e.g. "SQL Injection in /api/accounts (id parameter)"
Severity:     Critical / High / Medium / Low   (+ CVSS score if required)
OWASP / CWE:  A03 Injection / CWE-89
Location:     src/controllers/AccountController.cs : 42
Description:  what the code does and why it's exploitable (1-3 sentences)
Evidence:     the vulnerable code snippet (file:line)
Impact:       what an attacker achieves (read other users' data, RCE, etc.)
Remediation:  the fix, with a corrected code snippet
```

**Mini-glossary (every term, one line):**
- **Source** — where untrusted input enters (request param/body/header).
- **Sink** — a dangerous operation (query, command, HTML output, file path, URL fetch).
- **SAST** — scans source code for bug patterns (Semgrep). **SCA** — scans third-party libraries
  for known CVEs (Black Duck). **DAST** — tests the running app (Burp/ZAP).
- **CVE** — one specific known vulnerability id (e.g. CVE-2021-44228). **CWE** — a weakness
  *type* (e.g. CWE-89). **BDSA** — Black Duck's own advisory id (maps to a CVE).
- **BOM** — Bill of Materials: the full list of a project's components.
- **Parameterized query / prepared statement** — sends input separately from the SQL, preventing
  SQLi. **ORM** — library that maps objects to database rows (Hibernate, Entity Framework).
- **Transitive dependency** — a library pulled in by another library.
- **IV / ECB** — crypto settings that are unsafe when fixed/weak.

---

## References
- OWASP Top 10 — https://owasp.org/Top10/
- OWASP Code Review Guide — https://owasp.org/www-project-code-review-guide/
- OWASP Cheat Sheet Series — https://cheatsheetseries.owasp.org/
- Semgrep (SAST) — https://semgrep.dev/ · rules at https://semgrep.dev/explore
- Black Duck (SCA) — https://www.blackduck.com/
- OWASP Dependency-Check (free SCA) — https://owasp.org/www-project-dependency-check/
- gitleaks — https://github.com/gitleaks/gitleaks · trufflehog — https://github.com/trufflesecurity/trufflehog
- CWE Top 25 — https://cwe.mitre.org/top25/ · CWE list — https://cwe.mitre.org/
- OWASP ASVS (verification standard) — https://owasp.org/www-project-application-security-verification-standard/
- Practice code: OWASP WebGoat, OWASP Juice Shop (source), DVWA, OWASP Vulnerable Web Applications Directory
