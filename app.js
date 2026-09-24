const state = { scans: 0, findings: [], reports: 0, history: [] };
const $ = id => document.getElementById(id);
const esc = value => String(value).replace(/[&<>"']/g, character => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[character]));

function updateStats() {
  $('scanCount').textContent = state.scans;
  $('findingCount').textContent = state.findings.length;
  $('safeCount').textContent = state.scans;
  $('reportCount').textContent = state.reports;
  updateReport();
}

function recordScan(tool, findings) {
  state.scans += 1;
  state.findings = findings;
  state.history.push({ tool, findings: [...findings], time: new Date().toLocaleString() });
  updateStats();
}

function navigate(view) {
  document.querySelectorAll('.view').forEach(element => element.classList.toggle('active', element.id === view));
  document.querySelectorAll('[data-view]').forEach(element => element.classList.toggle('active', element.dataset.view === view));
  window.location.hash = view;
}

document.querySelectorAll('[data-view]').forEach(element => {
  element.addEventListener('click', () => navigate(element.dataset.view));
});
window.addEventListener('load', () => {
  const view = location.hash.slice(1);
  if ($(view)) navigate(view);
  updateStats();
});

$('themeToggle').addEventListener('click', () => document.body.classList.toggle('dark'));
$('showPassword').addEventListener('click', () => {
  const input = $('passwordInput');
  input.type = input.type === 'password' ? 'text' : 'password';
  $('showPassword').textContent = input.type === 'password' ? 'Show' : 'Hide';
});

function readFileInto(input, target) {
  input.addEventListener('change', () => {
    const file = input.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => $(target).value = reader.result;
    reader.onerror = () => $(target).value = '';
    reader.readAsText(file);
  });
}
readFileInto($('logFile'), 'logInput');
readFileInto($('codeFile'), 'codeInput');

$('checkPassword').addEventListener('click', () => {
  const password = $('passwordInput').value;
  const issues = [];
  let score = 0;
  if (password.length >= 12) score += 2; else issues.push('Use at least 12 characters.');
  if (/[a-z]/.test(password)) score++; else issues.push('Add a lowercase letter.');
  if (/[A-Z]/.test(password)) score++; else issues.push('Add an uppercase letter.');
  if (/\d/.test(password)) score++; else issues.push('Add a number.');
  if (/[^A-Za-z0-9]/.test(password)) score += 2; else issues.push('Add a special character.');
  if (/(.)\1{2,}/.test(password)) { score--; issues.push('Avoid repeated characters.'); }
  if (/password|admin|qwerty|letmein|welcome|1234|2024|2025|2026/i.test(password)) {
    score -= 2;
    issues.push('Avoid common password patterns.');
  }
  if (/^(.)\1+$/.test(password) || /^[a-z]+$/i.test(password)) {
    score -= 1;
    issues.push('Avoid predictable single-pattern passwords.');
  }
  score = Math.max(0, Math.min(8, score));
  const rating = score >= 7 ? 'Strong' : score >= 5 ? 'Moderate' : 'Weak';
  $('passwordResult').className = 'result';
  $('passwordResult').innerHTML =
    `<h3>Strength: ${rating}</h3><div class="score">${score}/8</div>` +
    `<div class="bar"><span style="width:${score / 8 * 100}%"></span></div>` +
    (issues.length ? `<ul>${issues.map(issue => `<li>${esc(issue)}</li>`).join('')}</ul>` :
      '<div class="finding safe">No major weaknesses detected by these local heuristics.</div>');
  recordScan('Password checker', issues.map(issue => `Password: ${issue}`));
});

$('analyzeLog').addEventListener('click', () => {
  const lines = $('logInput').value.split(/\r?\n/).filter(Boolean);
  const failed = lines.filter(line => /failed login|invalid password|authentication failed|login failure/i.test(line)).length;
  const alerts = lines.filter(line => /sql injection|command injection|cross[- ]site scripting|\bxss\b|unauthorized|privilege escalation|malware|ransomware/i.test(line)).length;
  const errors = lines.filter(line => /\berror\b|exception|stack trace|segmentation fault/i.test(line)).length;
  const suspiciousIps = new Set(lines.map(line => line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0]).filter(Boolean));
  const findings = [];
  if (failed >= 5) findings.push(`Possible brute force activity: ${failed} failed authentication events.`);
  if (alerts) findings.push(`${alerts} security alert pattern(s) detected.`);
  if (errors) findings.push(`${errors} error/exception line(s) detected for review.`);
  if (suspiciousIps.size >= 5) findings.push(`${suspiciousIps.size} distinct IP addresses appear in the log; review for distributed activity.`);
  $('logResult').className = 'result';
  $('logResult').innerHTML = `<h3>Log summary</h3><ul><li>Total lines: ${lines.length}</li>` +
    `<li>Failed authentication events: ${failed}</li><li>Security alerts: ${alerts}</li>` +
    `<li>Errors: ${errors}</li><li>Distinct IP addresses: ${suspiciousIps.size}</li></ul>` +
    (findings.length ? findings.map((finding, index) =>
      `<div class="finding ${index ? 'medium' : ''}">${esc(finding)}</div>`).join('') :
      '<div class="finding safe">No notable security patterns detected by these rules.</div>');
  recordScan('Log analyzer', findings);
});

const auditRules = [
  {
    name: 'Hardcoded secret', pattern: /(\bpassword\b|\bpasswd\b|\bsecret\b|\btoken\b|api[_ -]?key|private[_ -]?key|access[_ -]?token)\s*[:=]\s*["'][^"']+["']/gi,
    severity: 'HIGH', cwe: 'CWE-798', cvss: 'N/A', confidence: 'Medium',
    impact: 'A leaked credential can let an attacker access services or data.',
    fix: 'Revoke the exposed value and load secrets from a protected secret store or environment configuration.',
    priority: 'Fix immediately and rotate the credential.'
  },
  {
    name: 'SQL injection risk', pattern: /(executeQuery|executeUpdate|query\s*\(|SELECT[\s\S]{0,120}\+|SELECT[\s\S]{0,120}\$\{|SELECT[\s\S]{0,120}%\s)/gi,
    severity: 'HIGH', cwe: 'CWE-89', cvss: 'Potentially High; calculate after confirming reachability', confidence: 'Medium',
    impact: 'An attacker may modify a database query to read, change, or delete information.',
    fix: 'Use prepared statements or parameterized queries, and validate input at the application boundary.',
    priority: 'Fix before production deployment if user input can reach the query.'
  },
  {
    name: 'Command injection risk', pattern: /(Runtime\.getRuntime\(\)\.exec|ProcessBuilder|os\.system|subprocess\.(run|Popen|call)|child_process\.(exec|execSync))/gi,
    severity: 'HIGH', cwe: 'CWE-78', cvss: 'Potentially Critical; calculate after confirming input control', confidence: 'Medium',
    impact: 'Untrusted input may cause the application to execute unintended operating-system commands.',
    fix: 'Avoid shell execution; use safe APIs, strict allowlists, and validated fixed arguments.',
    priority: 'Fix before production deployment when any input is attacker-controlled.'
  },
  {
    name: 'Cross-site scripting risk', pattern: /(innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|v-html\s*=)/gi,
    severity: 'HIGH', cwe: 'CWE-79', cvss: 'Potentially High; calculate based on context', confidence: 'Medium',
    impact: 'Injected browser content may steal sessions or perform actions as a victim.',
    fix: 'Use contextual output encoding and safe DOM APIs; sanitize trusted HTML with a maintained sanitizer.',
    priority: 'Fix before release when the value can contain user-controlled content.'
  },
  {
    name: 'Path traversal risk', pattern: /(readFile|writeFile|open|FileInputStream|Paths?\.get)\s*\([^)]*(?:request|params|query|input|filename)/gi,
    severity: 'HIGH', cwe: 'CWE-22', cvss: 'Potentially High; calculate after confirming filesystem access', confidence: 'Low',
    impact: 'An attacker may use path sequences to access files outside the intended directory.',
    fix: 'Use a fixed base directory, normalize and constrain paths, and map user choices to allowlisted IDs.',
    priority: 'Review before production deployment.'
  },
  {
    name: 'Weak cryptography', pattern: /\b(MD5|SHA1|SHA-1|DES|3DES|RC4|ECB)\b/gi,
    severity: 'MEDIUM', cwe: 'CWE-327', cvss: 'Context dependent; do not assign from a pattern alone', confidence: 'High',
    impact: 'Weak algorithms may allow collisions, disclosure, or easier password recovery.',
    fix: 'Use current library guidance: Argon2id/bcrypt/scrypt for passwords and modern authenticated encryption for data.',
    priority: 'Replace before production or before protecting sensitive data.'
  },
  {
    name: 'Weak randomness', pattern: /(new\s+Random|Math\.random|random\.randint|random\.choice)/gi,
    severity: 'MEDIUM', cwe: 'CWE-338', cvss: 'Context dependent; do not assign from a pattern alone', confidence: 'Medium',
    impact: 'Predictable values can weaken tokens, identifiers, reset links, or security decisions.',
    fix: 'Use a platform cryptographic random generator for secrets, tokens, and security decisions.',
    priority: 'Fix when values are used in a security-sensitive context.'
  },
  {
    name: 'TLS verification disabled', pattern: /(verify\s*[:=]\s*false|rejectUnauthorized\s*:\s*false|TrustAll|disable[_ -]?hostname[_ -]?verification)/gi,
    severity: 'HIGH', cwe: 'CWE-295', cvss: 'Potentially High; calculate based on data and network exposure', confidence: 'High',
    impact: 'The application may accept an impersonated server and expose transmitted data.',
    fix: 'Keep certificate and hostname verification enabled; repair the trust chain instead of bypassing validation.',
    priority: 'Fix before production deployment.'
  },
  {
    name: 'Unsafe file write', pattern: /(FileWriter|FileOutputStream|Files\.write|fs\.writeFile|open\s*\([^)]*['"]w)/gi,
    severity: 'MEDIUM', cwe: 'CWE-73', cvss: 'Context dependent; do not assign from a pattern alone', confidence: 'Low',
    impact: 'Uncontrolled writes can overwrite files, expose data, or create unsafe server-side content.',
    fix: 'Constrain destinations, validate names, apply least-privilege permissions, and avoid writing sensitive content to logs.',
    priority: 'Review the destination and input flow before release.'
  },
  {
    name: 'Debug mode enabled', pattern: /(DEBUG\s*=\s*True|debug\s*[:=]\s*true|app\.run\s*\([^)]*debug\s*=\s*True)/gi,
    severity: 'MEDIUM', cwe: 'CWE-489', cvss: 'Context dependent; do not assign from a pattern alone', confidence: 'High',
    impact: 'Debug features can disclose stack traces, configuration, or interactive diagnostics.',
    fix: 'Disable debug mode in production and configure safe error handling and logging.',
    priority: 'Fix before production deployment.'
  }
];

$('auditCode').addEventListener('click', () => {
  const text = $('codeInput').value;
  const findings = [];
  auditRules.forEach(rule => {
    rule.pattern.lastIndex = 0;
    let match;
    while ((match = rule.pattern.exec(text)) !== null) {
      findings.push({ ...rule, line: text.slice(0, match.index).split(/\r?\n/).length });
    }
  });
  $('auditResult').className = 'result';
  $('auditResult').innerHTML = `<h3>Audit findings: ${findings.length}</h3>` +
    (findings.length ? findings.map(finding =>
      `<article class="finding finding-detail ${finding.severity === 'MEDIUM' ? 'medium' : ''}">
        <strong>${finding.severity}</strong> · ${esc(finding.name)} · line ${finding.line}
        <div class="finding-meta"><b>${esc(finding.cwe)}</b> · CVSS: ${esc(finding.cvss)} · Confidence: ${esc(finding.confidence)}</div>
        <p><b>What this means:</b> ${esc(finding.impact)}</p>
        <p><b>Why it matters:</b> ${esc(finding.impact)}</p>
        <p><b>What to do:</b> ${esc(finding.fix)}</p>
        <p><b>Priority:</b> ${esc(finding.priority)}</p>
        <small>CVEs are assigned to specific products and versions. This heuristic finding has no verified CVE mapping by itself.</small>
      </article>`).join('') :
      '<div class="finding safe">No known patterns detected by these rules.</div>');
  recordScan('Code audit', findings.map(finding => `${finding.severity} ${finding.name} (${finding.cwe}) line ${finding.line}`));
});

$('permissionFile').addEventListener('change', () => {
  const file = $('permissionFile').files[0];
  if (!file) return;
  $('permissionResult').className = 'result';
  $('permissionResult').innerHTML = `<h3>Browser-visible metadata</h3><ul>` +
    `<li>Name: ${esc(file.name)}</li><li>Size: ${file.size.toLocaleString()} bytes</li>` +
    `<li>Modified: ${esc(file.lastModified ? new Date(file.lastModified).toLocaleString() : 'Unknown')}</li>` +
    `<li>Type: ${esc(file.type || 'Unknown')}</li></ul>` +
    '<div class="finding medium">Operating-system permission bits are not available to web browsers. Use the Java companion for that check.</div>';
  recordScan('File metadata', ['File permissions require the local Java companion.']);
});

$('networkCheck').addEventListener('click', () => {
  const secure = window.isSecureContext || location.protocol === 'file:';
  $('networkResult').className = 'result';
  $('networkResult').innerHTML = `<h3>Local browser security context</h3><ul>` +
    `<li>Page protocol: ${esc(location.protocol)}</li><li>Secure context: ${secure ? 'Yes' : 'No'}</li>` +
    `<li>Origin: ${esc(location.origin === 'null' ? 'Local file' : location.origin)}</li></ul>` +
    `<div class="finding ${secure ? 'safe' : 'medium'}">${secure ? 'The page is running in a browser-protected context.' : 'Use HTTPS when hosting AlfaSec publicly.'}</div>`;
  recordScan('Network check', secure ? [] : ['Public deployment should use HTTPS.']);
});

function updateReport() {
  const entries = state.findings.length ? state.findings.map((finding, index) => `${index + 1}. ${finding}`).join('\n') : 'No findings recorded.';
  const history = state.history.length ? state.history.map(item =>
    `[${item.time}] ${item.tool}: ${item.findings.length ? item.findings.join('; ') : 'No findings'}`).join('\n') : 'No checks recorded.';
  $('reportPreview').textContent = `AlfaSec Security Report\nGenerated: ${new Date().toLocaleString()}\nScans: ${state.scans}\nCurrent findings: ${state.findings.length}\n\nCurrent findings\n${entries}\n\nCheck history\n${history}`;
}

$('exportReport').addEventListener('click', () => {
  updateReport();
  const blob = new Blob([$('reportPreview').textContent], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'alfasec-security-report.txt';
  link.click();
  URL.revokeObjectURL(url);
  state.reports += 1;
  updateStats();
});
