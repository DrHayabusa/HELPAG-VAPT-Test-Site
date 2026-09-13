const output = document.querySelector("#output");

async function run(path, method = "GET", body = null) {
  output.textContent = `${method} ${path}\n\nRunning…`;
  try {
    const options = { method, headers: { "Content-Type": "application/json" } };
    if (body) options.body = body;
    const response = await fetch(path, options);
    const text = await response.text();
    let formatted = text;
    try { formatted = JSON.stringify(JSON.parse(text), null, 2); } catch {}
    output.textContent = `${method} ${path}\nHTTP ${response.status}\n\n${formatted}`;
  } catch (error) {
    output.textContent = `Request failed: ${error.message}`;
  }
}

document.querySelectorAll("[data-path]").forEach((button) => button.addEventListener("click", () => run(
  button.dataset.path,
  button.dataset.method,
  button.dataset.body || null,
)));
document.querySelector("#runHealth").addEventListener("click", () => run("/health"));
document.querySelector("#clear").addEventListener("click", () => { output.textContent = "Select a lab demonstration above."; });

