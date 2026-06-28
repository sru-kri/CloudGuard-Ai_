// Screen and form elements
const authScreen = document.getElementById('auth-screen');
const consoleScreen = document.getElementById('console-screen');
const authForm = document.getElementById('auth-form');
const authMessage = document.getElementById('auth-message');
const submitBtn = document.getElementById('submit-btn');

// Tabs toggle elements
const tabLogin = document.getElementById('tab-login');
const tabSignup = document.getElementById('tab-signup');

let currentMode = 'login'; 
let findingsCache = [];    

// --- SWITCH BETWEEN LOGIN & SIGNUP VIEWS ---
tabLogin.addEventListener('click', () => {
    currentMode = 'login';
    tabLogin.classList.add('active');
    tabSignup.classList.remove('active');
    submitBtn.innerText = "Sign In";
    authMessage.innerText = "";
});

tabSignup.addEventListener('click', () => {
    currentMode = 'signup';
    tabSignup.classList.add('active');
    tabLogin.classList.remove('active');
    submitBtn.innerText = "Register Account";
    authMessage.innerText = "";
});

// --- HANDLE FORM SUBMISSIONS (LOGIN / SIGNUP) ---
authForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const usernameInput = document.getElementById('username').value;
    const passwordInput = document.getElementById('password').value;
    
    authMessage.innerText = "Connecting...";
    authMessage.style.color = "#fbbf24";

    if (currentMode === 'signup') {
        try {
            const response = await fetch('http://127.0.0.1:8000/signup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: usernameInput, password: passwordInput })
            });
            const data = await response.json();

            if (response.ok) {
                authMessage.innerText = "✅ Registration successful! Please Sign In.";
                authMessage.style.color = "#4ade80";
                tabLogin.click();
            } else {
                authMessage.innerText = `❌ ${data.detail || "Registration failed."}`;
                authMessage.style.color = "#ef4444";
            }
        } catch (err) {
            authMessage.innerText = "❌ Cannot connect to backend server.";
        }
    } else {
        try {
            const response = await fetch('http://127.0.0.1:8000/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: usernameInput, password: passwordInput })
            });
            const data = await response.json();

            if (response.ok) {
                localStorage.setItem('token', data.access_token);
                authScreen.classList.add('hidden');
                consoleScreen.classList.remove('hidden');
                authForm.reset();
            } else {
                authMessage.innerText = `❌ ${data.detail || "Invalid credentials."}`;
                authMessage.style.color = "#ef4444";
            }
        } catch (err) {
            authMessage.innerText = "❌ Connection failed.";
        }
    }
});

// --- LOG OUT ACTION ---
document.getElementById('logout-btn').addEventListener('click', () => {
    localStorage.removeItem('token');
    consoleScreen.classList.add('hidden');
    authScreen.classList.remove('hidden');
    authMessage.innerText = "Logged out securely.";
    authMessage.style.color = "#94a3b8";
});

// --- RUN COMPLIANCE RULE ENGINE SCAN & RENDER TARGETS ---
document.getElementById('scan-btn').addEventListener('click', async () => {
    const statusText = document.getElementById('status-text');
    const summarySection = document.getElementById('results-summary');
    const filterSection = document.getElementById('filter-bar-section');
    const reportSection = document.getElementById('report-section');

    statusText.innerText = "⏳ AI Engine auditing cloud configurations...";
    statusText.className = "status-scanning";
    
    try {
        const scanResponse = await fetch('http://127.0.0.1:8000/api/v1/compliance/scan', { method: 'POST' });
        if (!scanResponse.ok) throw new Error("Compliance scan loop failure.");

        const findingsResponse = await fetch('http://127.0.0.1:8000/api/v1/findings');
        findingsCache = await findingsResponse.json();

        processAndRenderDashboard(findingsCache);

        statusText.innerText = "✅ Scan Complete. AI Analytics report metrics generated!";
        statusText.className = "status-idle";
        summarySection.classList.remove('hidden');
        if(filterSection) filterSection.classList.remove('hidden');
        reportSection.classList.remove('hidden');

    } catch (error) {
        statusText.innerText = "❌ Error processing security evaluation rules.";
        statusText.className = "status-idle";
    }
});

// --- RENDER COUNTS, CARDS & TABLES ---
function processAndRenderDashboard(findings) {
    const container = document.getElementById('reports-container');
    const tableBody = document.getElementById('findings-table-body');
    
    container.innerHTML = "";
    tableBody.innerHTML = "";

    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;

    findings.forEach(item => {
        if (item.severity === "CRITICAL") criticalCount++;
        if (item.severity === "HIGH") highCount++;
        if (item.severity === "MEDIUM") mediumCount++;

        // Render Cards
        const card = document.createElement('div');
        card.className = 'ai-card';
        card.style.cssText = "background: #1e293b; padding: 16px; border-radius: 8px; margin-bottom: 1rem; border-left: 4px solid #3b82f6;";
        
        if(item.severity === "CRITICAL") card.style.borderLeftColor = "#ef4444";
        if(item.severity === "HIGH") card.style.borderLeftColor = "#f97316";
        if(item.severity === "MEDIUM") card.style.borderLeftColor = "#eab308";

        card.innerHTML = `
            <span class="severity-tag severity-${item.severity.toLowerCase()}" style="padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8rem;">${item.severity}</span>
            <h3 style="margin: 8px 0; color: #38bdf8;">${item.rule_name}</h3>
            <p style="color: #94a3b8; font-size: 0.9rem; margin: 4px 0;">Resource ID: <code>${item.resource_id}</code></p>
            <p style="margin: 6px 0; font-size: 0.95rem;">${item.description}</p>
            <pre style="background: #0f172a; color: #4ade80; padding: 12px; border-radius: 6px; border-left: 3px solid #38bdf8; font-family: monospace; font-size: 0.9rem; overflow-x: auto; white-space: pre-wrap; margin-top: 8px;"><code>${item.remediation}</code></pre>
        `;
        container.appendChild(card);

        // Render dynamic table rows
        const row = document.createElement('tr');
        row.style.borderBottom = "1px solid #334155";
        row.innerHTML = `
            <td style="padding: 0.75rem;"><code>${item.resource_id}</code></td>
            <td style="padding: 0.75rem;"><span style="background: #475569; padding: 2px 6px; border-radius: 4px; font-size: 0.8rem;">${item.resource_type}</span></td>
            <td style="padding: 0.75rem;"><span style="color: #38bdf8; font-weight: 500;">${item.rule_name}</span></td>
            <td style="padding: 0.75rem;"><span style="font-weight: bold; color: ${item.severity === 'CRITICAL' ? '#ef4444' : item.severity === 'HIGH' ? '#f97316' : '#eab308'}">${item.severity}</span></td>
            <td style="padding: 0.75rem;">
                <p style="margin-bottom: 6px; color: #e2e8f0; font-size: 0.9rem;">${item.description}</p>
                <pre style="background: #0f172a; color: #4ade80; padding: 8px; border-radius: 4px; font-family: monospace; font-size: 0.85rem; border: 1px solid #1e293b; overflow-x: auto; white-space: pre-wrap; margin: 0;"><code>${item.remediation}</code></pre>
            </td>
        `;
        tableBody.appendChild(row);
    });

    // Update scoreboard elements
    document.getElementById('vuln-count-critical').innerText = criticalCount;
    document.getElementById('vuln-count-high').innerText = highCount;
    document.getElementById('vuln-count-medium').innerText = mediumCount;

    // Dynamic Risk Score calculation
    const calculatedRiskValue = (criticalCount * 12) + (highCount * 6) + (mediumCount * 3);
    document.getElementById('risk-score-pct').innerText = `${Math.min(calculatedRiskValue, 100)}%`;
}

// --- SEARCH AND FILTER HANDLERS ---
function performFilteringActions() {
    const searchString = document.getElementById('search-bar').value.toLowerCase();
    const selectedSeverity = document.getElementById('severity-filter').value;

    const filteredResultSet = findingsCache.filter(issue => {
        const matchesSearch = issue.resource_id.toLowerCase().includes(searchString) || 
                              issue.rule_name.toLowerCase().includes(searchString) ||
                              issue.description.toLowerCase().includes(searchString);
        
        const matchesSeverity = (selectedSeverity === "ALL") || (issue.severity === selectedSeverity);
        return matchesSearch && matchesSeverity;
    });

    processAndRenderDashboard(filteredResultSet);
}

document.getElementById('search-bar').addEventListener('input', performFilteringActions);
document.getElementById('severity-filter').addEventListener('change', performFilteringActions);

// --- PASSWORD VISIBILITY TOGGLE FEATURE (STANDARD ICON FIX) ---
const passwordInput = document.getElementById('password');
const togglePasswordBtn = document.getElementById('toggle-password');
const eyeIcon = document.getElementById('eye-icon');

togglePasswordBtn.addEventListener('click', () => {
    // Check if password type is password or text
    const isPassword = passwordInput.getAttribute('type') === 'password';
    passwordInput.setAttribute('type', isPassword ? 'text' : 'password');
    
    // Dynamically change icon class to regular slashed/unslashed view
    if (isPassword) {
        eyeIcon.className = "fas fa-eye-slash";
    } else {
        eyeIcon.className = "fas fa-eye";
    }
});