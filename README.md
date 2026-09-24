# AlfaSec

AlfaSec is a privacy-first defensive security toolkit with a single dashboard and separate security checks:

- Password strength checker
- Log analyzer
- Lightweight source-code audit
- Browser-visible file metadata check
- Local network security-context check
- Plain-text report export

The web app is static and can be hosted on GitHub Pages. Analysis runs in the browser; files are not uploaded and the network check does not call an external IP service. A browser cannot inspect operating-system permission bits or safely scan arbitrary ports, so the existing Java `SecurityToolkit` remains the companion for those local checks.

The code audit is a heuristic scanner that covers hardcoded secrets, SQL injection patterns, command execution, XSS sinks, path traversal, weak cryptography/randomness, disabled TLS verification, unsafe writes, and debug mode. Each finding includes a CWE mapping, confidence, impact, remediation, priority, and a CVSS note. CVE identifiers are not invented: a CVE requires a verified affected product/version mapping from a vulnerability database. The scanner is not a complete SAST engine; findings require human review and the absence of a finding is not proof of safety.

## Run locally

Open `index.html` in a browser, or serve this folder with any static web server:

```text
python -m http.server 8000
```

Then open `http://localhost:8000`.

## Publish with GitHub Pages

1. Create a GitHub repository named `alfasec`.
2. Upload `index.html`, `styles.css`, `app.js`, and `README.md`.
3. Open **Settings → Pages**.
4. Select **Deploy from a branch**, choose `main` and `/ (root)`, then save.
5. GitHub will provide a URL similar to `https://YOUR-USERNAME.github.io/alfasec/`.

This app does not include a backend or authentication. Do not treat browser results as a complete penetration test or upload confidential source code to a public repository. Only scan assets you own or are authorized to assess.
