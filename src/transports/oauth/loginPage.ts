function escapeHtml(value: string): string {
    return value
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

export function renderLoginPage(options: {
    authorizeQuery: string;
    error?: string;
}): string {
    const nextPath = `/authorize?${options.authorizeQuery}`;
    const errorHtml = options.error
        ? `<p class="error">${escapeHtml(options.error)}</p>`
        : "";
    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Sign in</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         background: #0b1020; color: #e6e9f2; display: flex; align-items: center;
         justify-content: center; min-height: 100vh; margin: 0; }
  .card { background: #141a33; padding: 2rem 2.25rem; border-radius: 12px;
          box-shadow: 0 10px 40px rgba(0,0,0,0.4); width: 320px; }
  h1 { font-size: 1.1rem; margin: 0 0 1rem; }
  label { display: block; font-size: 0.85rem; margin-bottom: 0.5rem; color: #aab3c8; }
  input[type=password] { width: 100%; padding: 0.6rem 0.7rem; border-radius: 6px;
                         border: 1px solid #2a3355; background: #0b1020;
                         color: #e6e9f2; font-size: 0.95rem; box-sizing: border-box; }
  button { margin-top: 1rem; width: 100%; padding: 0.6rem; border-radius: 6px;
           border: none; background: #5569ff; color: white; font-weight: 600;
           font-size: 0.95rem; cursor: pointer; }
  button:hover { background: #6678ff; }
  .error { color: #ff8a8a; font-size: 0.85rem; margin: 0 0 0.75rem; }
  .hint { font-size: 0.75rem; color: #8892b0; margin-top: 1rem; }
</style>
</head>
<body>
<div class="card">
  <h1>MongoDB MCP — Sign in</h1>
  ${errorHtml}
  <form method="POST" action="/oauth/login">
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autofocus required />
    <input type="hidden" name="next" value="${escapeHtml(nextPath)}" />
    <button type="submit">Continue</button>
  </form>
  <p class="hint">This server is protected. Enter the shared password to grant access.</p>
</div>
</body>
</html>`;
}
