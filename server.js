const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const fs = require('fs');

const app = express();
const PORT = 8080;
const DB_FILE = './nanords.db';
const CONFIG_FILE = './config.json';

// Whitelisted parameters as requested + AF and DI added
const ALLOWED_FIELDS = ['PS', 'RT', 'PTY', 'PI', 'PTYN', 'LIC', 'ECC', 'MS', 'TP', 'TA', 'RDS', 'STEREO', 'AF', 'DI'];

// --- Middleware ---
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'nanords-super-secret-key-change-in-prod',
    resave: false,
    saveUninitialized: false
}));

// --- Database Setup ---
const db = new sqlite3.Database(DB_FILE);
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);
});

const checkSetup = (req, res, next) => {
    db.get("SELECT COUNT(*) AS count FROM users", (err, row) => {
        if (err) return res.status(500).send("Database error");
        if (row.count === 0 && req.path !== '/setup') return res.redirect('/setup');
        if (row.count > 0 && req.path === '/setup') return res.redirect('/login');
        next();
    });
};

const requireAuth = (req, res, next) => {
    if (!req.session.userId) return res.redirect('/login');
    next();
};

app.use(checkSetup);

// --- Routes ---

app.get('/setup', (req, res) => res.send(renderAuthPage("Setup NanoRDS", "/setup", "Create Admin Account", "Create Account")));
app.post('/setup', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.send(renderAuthPage("Setup NanoRDS", "/setup", "Create Admin Account", "Create Account", "Username and password required."));
    const hash = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hash], (err) => {
        if (err) return res.send(renderAuthPage("Setup NanoRDS", "/setup", "Create Admin Account", "Create Account", "Error creating user."));
        res.redirect('/login');
    });
});

app.get('/login', (req, res) => {
    if (req.session.userId) return res.redirect('/');
    res.send(renderAuthPage("Login", "/login", "NanoRDS WebUI", "Unlock"));
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.regenerate(() => {
                req.session.userId = user.id;
                res.redirect('/');
            });
        } else {
            res.send(renderAuthPage("Login", "/login", "NanoRDS WebUI", "Unlock", "Invalid credentials."));
        }
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.get('/', requireAuth, (req, res) => {
    let config = { fifo_path: "/tmp/rds_fifo", fields: {} };
    if (fs.existsSync(CONFIG_FILE)) {
        try { config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); } catch (e) {}
    }
    res.send(renderDashboard(config, req.query.success)); 
});

app.post('/update', requireAuth, (req, res) => {
    const updates = req.body.data;
    
    if (!updates) {
        return res.redirect('/?error=' + encodeURIComponent('No data received!'));
    }

    let config = { fifo_path: "/tmp/rds_fifo", fields: {} };
    if (fs.existsSync(CONFIG_FILE)) {
        try { config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); } catch (e) {}
    }
    
    if (!config.fields) config.fields = {};

    for (const [field, data] of Object.entries(updates)) {
        if (ALLOWED_FIELDS.includes(field)) {
            if (!config.fields[field]) config.fields[field] = {};
            config.fields[field].mode = data.mode || 'static';
            config.fields[field].value = data.value !== undefined ? data.value : '';
        }
    }
    
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 4));

    if (req.headers['content-type'] === 'application/x-www-form-urlencoded' && req.headers['x-requested-with'] === 'XMLHttpRequest') {
        return res.sendStatus(200);
    }
    
    res.redirect('/?success=' + encodeURIComponent('All changes applied successfully!'));
});

app.post('/reset', requireAuth, (req, res) => {
    let config = { fifo_path: "/tmp/rds_fifo", fields: {} };
    if (fs.existsSync(CONFIG_FILE)) {
        try { config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); } catch (e) {}
    }
    
    if (!config.fields) config.fields = {};

    // Restore specified default values
    config.fields['PS'] = { mode: 'static', value: 'NanoRDS' };
    config.fields['RT'] = { mode: 'static', value: 'NanoRDS - software RDS encoder for Linux' };
    config.fields['PI'] = { mode: 'static', value: '1000' };
    config.fields['ECC'] = { mode: 'static', value: '' };
    config.fields['LIC'] = { mode: 'static', value: '' };
    config.fields['PTYN'] = { mode: 'static', value: '' };
    config.fields['MS'] = { mode: 'static', value: '0' };
    config.fields['TP'] = { mode: 'static', value: '0' };
    config.fields['TA'] = { mode: 'static', value: '0' };
    config.fields['DI'] = { mode: 'static', value: '1' }; // 1 = Only Stereo by default
    config.fields['RDS'] = { mode: 'static', value: '4' };
    config.fields['STEREO'] = { mode: 'static', value: '9' };

    // Save defaults to file
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 4));

    // Send the RESET command to the hardware if pipe is available
    if (config.fifo_path && fs.existsSync(config.fifo_path) && fs.lstatSync(config.fifo_path).isFIFO()) {
        try { fs.writeFileSync(config.fifo_path, "RESET\n"); } catch(e) { }
    }

    // Clear caches so the worker resends ALL configurations on the next cycle
    lastSent = {};
    fileCache = {}; // <-- ADDED: Clear the file cache

    res.redirect('/?success=' + encodeURIComponent('System reset and restored to defaults!'));
});

app.post('/update-settings', requireAuth, (req, res) => {
    const { fifo_path } = req.body;
    let config = { fifo_path: "/tmp/rds_fifo", fields: {} };
    if (fs.existsSync(CONFIG_FILE)) {
        try { config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); } catch (e) {}
    }
    
    if (fifo_path) {
        config.fifo_path = fifo_path;
        fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 4));
    }
    res.redirect('/?success=' + encodeURIComponent('System settings saved!'));
});

// --- Helper: Convert to ASCII ---
function toAscii(str) {
    if (typeof str !== 'string') return str;
    
    const specialChars = {
        'ł': 'l', 'Ł': 'L', 'đ': 'd', 'Đ': 'D', 'ß': 'ss',
        'æ': 'ae', 'Æ': 'AE', 'œ': 'oe', 'Œ': 'OE', 'ø': 'o', 'Ø': 'O'
    };
    
    let asciiStr = str.replace(/[łŁđĐßæÆœŒøØ]/g, match => specialChars[match]);

    return asciiStr.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^\x00-\x7F]/g, "");
}

// --- Background FIFO Sync Worker ---
let lastSent = {};
let fileCache = {}; // Cache to track file modification times

setInterval(async () => {
    try {
        if (!fs.existsSync(CONFIG_FILE)) return;
        const config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
        const fifoPath = config.fifo_path;

        if (!fs.existsSync(fifoPath) || !fs.lstatSync(fifoPath).isFIFO()) return;

        for (const cmd of ALLOWED_FIELDS) {
            if (!config.fields || config.fields[cmd] === undefined) continue;
            
            const data = config.fields[cmd];
            let value = "";
            
            if (data.mode === 'static') {
                value = data.value !== undefined ? data.value : "";
            } else if (data.mode === 'file') {
                if (fs.existsSync(data.value)) {
                    try {
                        const stats = fs.statSync(data.value);
                        
                        // RACE CONDITION FIX: 
                        // Only read and update cache if the file has data (> 0 bytes).
                        // This prevents empty reads when 3rd party software is mid-write.
                        if (stats.size > 0 && (!fileCache[cmd] || fileCache[cmd].path !== data.value || fileCache[cmd].mtimeMs !== stats.mtimeMs)) {
                            const content = fs.readFileSync(data.value, 'utf8').trim();
                            fileCache[cmd] = {
                                path: data.value,
                                mtimeMs: stats.mtimeMs,
                                content: content
                            };
                        }
                        
                        // Fallback to cache if available
                        value = fileCache[cmd] ? fileCache[cmd].content : "";
                    } catch (e) {
                        value = ""; 
                    }
                } else {
                    if (fileCache[cmd]) delete fileCache[cmd]; 
                }
            } else if (data.mode === 'url') {
                try {
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => controller.abort(), 2000);
                    const response = await fetch(data.value, { signal: controller.signal });
                    clearTimeout(timeoutId);
                    if (response.ok) value = (await response.text()).trim();
                } catch (e) { continue; }
            }

            if (value !== undefined) {
                value = toAscii(value);
            }

            // Only trigger send if the value is valid and actually changed
            if (value !== undefined && value !== "" && lastSent[cmd] !== value) {
                if (cmd === 'AF') {
                    try {
                        let commandStr = "AF c\n";
                        if (value.trim() !== "") {
                            commandStr += `AF s ${value.trim()}\n`;
                        }
                        fs.writeFileSync(fifoPath, commandStr);
                    } catch(e) { }
                } else {
                    try { fs.writeFileSync(fifoPath, `${cmd.toUpperCase()} ${value}\n`); } catch(e) { }
                }
                lastSent[cmd] = value;
            }
        }
    } catch (e) { /* Fail silently */ }
}, 1000);

// --- UI Render Functions ---
function renderAuthPage(title, actionUrl, headerText, btnText, errorMsg = "") {
    let errorHtml = errorMsg ? `<div class="error-box">${errorMsg}</div>` : '';
    let finalBtnText = btnText === 'Unlock' ? 'Login' : btnText;

    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="icon" type="image/x-icon" href="/favicon.ico">
        <title>${title} | NanoRDS WebUI</title>
        <script src="https://unpkg.com/lucide@latest"></script>
        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;700&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="/style.css">
    </head>
    <body class="auth-body">
        <div class="glass-card auth-card">
            <h1 class="auth-title">
                 NanoRDS <span>WebUI</span>
            </h1>
            ${errorHtml}
            <form method="POST" action="${actionUrl}" class="auth-form">
                <input type="text" name="username" required autofocus class="input-field" placeholder="Username">
                <input type="password" name="password" required class="input-field" placeholder="Password">
                <button type="submit" class="btn btn-submit">
                    ${finalBtnText} <i data-lucide="${actionUrl === '/setup' ? 'user-plus' : 'log-in'}" class="w-4 h-4"></i>
                </button>
            </form>
        </div>
        <script>lucide.createIcons();</script>
    </body>
    </html>`;
}

function renderDashboard(config, successMsg = "") {
    let fifoWarning = "";
    try {
        if (!fs.existsSync(config.fifo_path)) {
            fifoWarning = `The FIFO pipe <strong>"${config.fifo_path || 'not set'}"</strong> does not exist. Please start your encoder or create the pipe manually.`;
        } else if (!fs.lstatSync(config.fifo_path).isFIFO()) {
            fifoWarning = `The path <strong>"${config.fifo_path}"</strong> exists but is a regular file, not a pipe. Updates will not reach the encoder.`;
        }
    } catch(e) { fifoWarning = "Could not verify FIFO pipe status."; }

    const afData = (config.fields && config.fields['AF']) ? config.fields['AF'].value : '';
    const afList = afData ? afData.split(' ').filter(Boolean) : [];

    const placeholderMap = { 'PS': 'Max. 8 chars', 'RT': 'Max. 64 chars', 'PI': '4-digit HEX', 'PTYN': 'PTYN Program Type Name', 'LIC': 'LIC code', 'ECC': 'ECC code', 'PTY': 'PTY code', 'TP': '0 or 1', 'TA': '0 or 1', 'MS': '0 or 1', 'RDS': 'RDS Vol', 'STEREO': 'Pilot Vol' };
    
    const subtitleMap = {
        'PS': 'Program Service',
        'RT': 'Radio Text',
        'PTY': 'Program Type',
        'PTYN': 'Program Type Name',
        'PI': 'Program Identification',
        'LIC': 'Language Identification Code',
        'ECC': 'Extended Country Code',
        'MS': 'Music / Speech Switch',
        'TP': 'Traffic Program',
        'TA': 'Traffic Announcement',
        'RDS': 'RDS Subcarrier Level',
        'STEREO': 'Stereo Pilot Level',
        'DI': 'Decoder Information'
    };

    function generateCardHtml(key, isBinary = false, offLabel = '0', onLabel = '1') {
        const data = (config.fields && config.fields[key]) ? config.fields[key] : { mode: 'static', value: '' };
        const mode = data.mode || 'static';
        let inputHtml = '';
        let safeValue = data.value ? data.value.replace(/"/g, '&quot;') : '';

        let currentPlaceholder = "";
        if (mode === 'static') currentPlaceholder = placeholderMap[key] || 'Value';
        else if (mode === 'file') currentPlaceholder = "/path/to/data.txt";
        else currentPlaceholder = "https://example.com/api/rds";

        if (isBinary) {
            const isChecked = (data.value === '1' || String(data.value).toUpperCase() === 'ON' || String(data.value).toUpperCase() === 'M');
            
            inputHtml = `
            <div class="input-wrapper input-field flex items-center h-46 px-4">
                <div id="toggle-container-${key}" class="toggle-container ${mode === 'static' ? '' : 'hidden'}">
                    <label class="toggle-label">
                        <input type="checkbox" id="checkbox-${key}" class="sr-only" ${isChecked ? 'checked' : ''} onchange="
                            document.getElementById('input-${key}').value = this.checked ? '1' : '0';
                            document.getElementById('status-${key}').innerText = this.checked ? '${onLabel}' : '${offLabel}';
                            document.getElementById('status-${key}').className = this.checked ? 'toggle-text active' : 'toggle-text';
                        ">
                        <div class="toggle-bg"></div>
                        <span id="status-${key}" data-off="${offLabel}" data-on="${onLabel}" class="toggle-text ${isChecked ? 'active' : ''}">${isChecked ? onLabel : offLabel}</span>
                    </label>
                </div>
                
                <input type="text" id="input-${key}" name="data[${key}][value]" value="${safeValue}" class="w-full bg-transparent border-none outline-none text-sm font-mono ${mode === 'static' ? 'hidden' : ''}" placeholder="${currentPlaceholder}">
            </div>`;
        } else {
            inputHtml = `
            <div class="input-wrapper">
                <input type="text" id="input-${key}" name="data[${key}][value]" value="${safeValue}" data-static-placeholder="${placeholderMap[key] || 'Value'}" class="input-field text-sm font-mono" placeholder="${currentPlaceholder}">
            </div>`;
        }

        return `
        <div class="glass-card param-card align-start">
            <div class="card-header">
                <div class="card-title-box">
                    <span class="card-title">${key}</span>
                    <span class="card-subtitle">${subtitleMap[key] || 'Parameter'}</span>
                </div>
                <div class="mode-switch">
                    <button type="button" onclick="setMode('${key}', 'static')" id="btn-static-${key}" class="mode-btn ${mode === 'static' ? 'active' : ''}">STATIC</button>
                    <button type="button" onclick="setMode('${key}', 'file')" id="btn-file-${key}" class="mode-btn ${mode === 'file' ? 'active' : ''}">FILE</button>
                    <button type="button" onclick="setMode('${key}', 'url')" id="btn-url-${key}" class="mode-btn ${mode === 'url' ? 'active' : ''}">URL</button>
                    <input type="hidden" name="data[${key}][mode]" id="mode-${key}" value="${mode}">
                </div>
            </div>
            <div class="form-group">
                ${inputHtml}
            </div>
        </div>`;
    }

    function generateDICardHtml() {
        const data = (config.fields && config.fields['DI']) ? config.fields['DI'] : { mode: 'static', value: '1' };
        const mode = data.mode || 'static';
        let safeValue = parseInt(data.value);
        if (isNaN(safeValue)) safeValue = 1;

        const isStereo = (safeValue & 1) !== 0;
        const isArtHead = (safeValue & 2) !== 0;
        const isComp = (safeValue & 4) !== 0;
        const isDynPty = (safeValue & 8) !== 0;

        function makeDIToggle(label, checked, val) {
            return `
            <div class="di-toggle-row">
                <span class="text-sm font-mono">${label}</span>
                <label class="toggle-label di-toggle-label">
                    <input type="checkbox" id="di-cb-${val}" class="sr-only" value="${val}" ${checked ? 'checked' : ''} onchange="updateDI()">
                    <div class="toggle-bg"></div>
                </label>
            </div>`;
        }

        return `
        <div class="glass-card param-card di-card">
            <div class="card-header">
                <div class="card-title-box">
                    <span class="card-title">DI</span>
                    <span class="card-subtitle">Decoder Information</span>
                </div>
                <div class="mode-switch">
                    <button type="button" onclick="setMode('DI', 'static')" id="btn-static-DI" class="mode-btn ${mode === 'static' ? 'active' : ''}">STATIC</button>
                    <button type="button" onclick="setMode('DI', 'file')" id="btn-file-DI" class="mode-btn ${mode === 'file' ? 'active' : ''}">FILE</button>
                    <button type="button" onclick="setMode('DI', 'url')" id="btn-url-DI" class="mode-btn ${mode === 'url' ? 'active' : ''}">URL</button>
                    <input type="hidden" name="data[DI][mode]" id="mode-DI" value="${mode}">
                </div>
            </div>
            <div class="form-group di-form-group">
                <div class="input-wrapper input-field flex-col items-start px-4 py-4 h-auto di-input-wrapper">
                    <div id="toggle-container-DI" class="w-full ${mode === 'static' ? '' : 'hidden'}">
                        <div class="di-toggle-list">
                            ${makeDIToggle('Stereo', isStereo, 1)}
                            ${makeDIToggle('Artificial Head', isArtHead, 2)}
                            ${makeDIToggle('Compressed', isComp, 4)}
                            ${makeDIToggle('Dynamic PTY', isDynPty, 8)}
                        </div>
                    </div>
                    
                    <input type="text" id="input-DI" name="data[DI][value]" value="${safeValue}" class="w-full bg-transparent border-none outline-none text-sm font-mono ${mode === 'static' ? 'hidden' : ''}" placeholder="${mode === 'file' ? '/path/to/data.txt' : 'https://example.com/api/rds'}">
                </div>
            </div>
        </div>`;
    }

    const parametersHtml = 
        generateCardHtml('PS') +
        generateCardHtml('RT') +
        generateCardHtml('PTY') +
        generateCardHtml('PTYN') +
        generateCardHtml('LIC') +
        generateCardHtml('ECC') +
        generateCardHtml('PI') +
        generateCardHtml('MS', true, 'S', 'M') +
        generateCardHtml('TP', true, '0', '1') +
        generateCardHtml('TA', true, '0', '1');

    const mpxHtml = 
        generateCardHtml('RDS') +
        generateCardHtml('STEREO');

    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="icon" type="image/x-icon" href="/favicon.ico">
        <title>NanoRDS WebUI</title>
        <script src="https://unpkg.com/lucide@latest"></script>
        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;700&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="/style.css">
    </head>
    <body class="dash-body">
        <div class="main-container">
        <header class="header">
            <h1 class="header-title">
                NanoRDS <span>WebUI</span>
            </h1>

            <div class="header-actions">
                <div class="header-main">
                    <form id="reset-form" method="POST" action="/reset" class="hidden"></form>
                    <button type="button" onclick="if(confirm('Are you sure you want to reset defaults? This will erase current settings and restart the hardware stream.')) document.getElementById('reset-form').submit();" class="btn btn-reset">
                        <i data-lucide="power" class="w-4 h-4"></i> Reset
                    </button>

                    <button type="submit" form="main-config-form" class="btn btn-apply">
                        <i data-lucide="check-check" class="w-4 h-4"></i> Apply Changes
                    </button>
                </div>
                    
                <div class="divider"></div>
                    
                <div class="header-utils">
                    <button type="button" onclick="openSettings()" class="btn btn-icon"><i data-lucide="settings" class="w-4 h-4"></i></button>
                        <a href="/logout" class="btn btn-logout"><i data-lucide="log-out" class="w-4 h-4"></i> Logout</a>
                </div>
            </div>
        </header>

            ${fifoWarning ? `
            <div class="alert-danger">
                <div class="alert-icon"><i data-lucide="alert-triangle"></i></div>
                <div><h3 class="alert-title">Hardware Link Error</h3><p class="alert-text">${fifoWarning}</p></div>
            </div>` : ''}

            <div class="tabs">
                <button onclick="switchTab('parameters')" id="tab-btn-parameters" class="btn tab-btn active">
                    <i data-lucide="sliders" class="w-4 h-4"></i> Parameters
                </button>
                <button onclick="switchTab('mpx')" id="tab-btn-mpx" class="btn tab-btn">
                    <i data-lucide="activity" class="w-4 h-4"></i> MPX Settings
                </button>
                <button onclick="switchTab('af')" id="tab-btn-af" class="btn tab-btn">
                    <i data-lucide="radio" class="w-4 h-4"></i> AF & DI
                </button>
            </div>

            <form id="main-config-form" method="POST" action="/update">
                <div id="tab-content-parameters" class="tab-content active grid-cards">
                    ${parametersHtml}
                </div>
                
                <div id="tab-content-mpx" class="tab-content grid-cards">
                    ${mpxHtml}
                </div>

                <div id="tab-content-af" class="tab-content grid-cards">
                    ${generateDICardHtml()}
                    <div class="glass-card param-card af-card align-start">
                        <div class="flex justify-between items-start w-full mb-2">
                            <div>
                                <h2 class="af-header" style="margin-bottom: 2px;">Alternative Frequencies</h2>
                                <p class="af-desc">Manage frequencies. Click 'Apply Changes' to save.</p>
                            </div>
                            <button type="button" onclick="clearAF()" class="btn btn-reset" style="padding: 6px 12px; font-size: 0.85rem; height: fit-content;">
                                <i data-lucide="trash-2" class="w-4 h-4"></i> Clear AF
                            </button>
                        </div>
                        
                        <div class="af-input-row">
                            <input type="text" id="af-input" class="input-field font-mono" placeholder="Add frequency (e.g., 100.5)">
                            <button type="button" onclick="addAF()" class="btn btn-add">Add</button>
                        </div>

                        <input type="hidden" name="data[AF][mode]" id="mode-AF" value="static">
                        <input type="hidden" name="data[AF][value]" id="input-AF" value="${afData}">

                        <div id="af-container" class="af-list">
                        </div>
                    </div>
                </div>
            </form>
        </div>

        <div id="settingsModal" class="modal">
            <div class="modal-overlay" onclick="closeSettings()"></div>
            <div class="glass-card modal-content" id="settingsCard">
                <button onclick="closeSettings()" class="btn btn-close">
                    <i data-lucide="x" class="w-5 h-5"></i>
                </button>
                <h2 class="modal-title"><i data-lucide="settings-2"></i> System Settings</h2>
                <form method="POST" action="/update-settings">
                    <div>
                        <label class="form-label">FIFO Path</label>
                        <input type="text" name="fifo_path" value="${config.fifo_path || ''}" class="input-field font-mono" required>
                    </div>
                    <button type="submit" class="btn btn-apply w-full mt-4">
                        Save Configuration
                    </button>
                </form>
            </div>
        </div>

        ${successMsg ? `<div id="toast" class="toast"><i data-lucide="check-circle" class="w-5 h-5"></i> ${successMsg}</div><script>setTimeout(()=>document.getElementById('toast').remove(),3000);window.history.replaceState({},'',window.location.pathname);</script>` : ''}

        <script>
            lucide.createIcons();

            function switchTab(tabId) {
                ['parameters', 'mpx', 'af'].forEach(id => {
                    const btn = document.getElementById('tab-btn-' + id);
                    const content = document.getElementById('tab-content-' + id);
                    if(id === tabId) {
                        btn.className = "btn tab-btn active";
                        content.classList.add('active');
                    } else {
                        btn.className = "btn tab-btn";
                        content.classList.remove('active');
                    }
                });
            }

            function updateDI() {
                let val = 0;
                if (document.getElementById('di-cb-1').checked) val += 1;
                if (document.getElementById('di-cb-2').checked) val += 2;
                if (document.getElementById('di-cb-4').checked) val += 4;
                if (document.getElementById('di-cb-8').checked) val += 8;
                
                document.getElementById('input-DI').value = val;
                if (document.getElementById('di-val-display')) {
                    document.getElementById('di-val-display').innerText = val;
                }
            }

            function setMode(field, newMode) {
                const modeInput = document.getElementById('mode-' + field);
                const inputField = document.getElementById('input-' + field);
                const toggleContainer = document.getElementById('toggle-container-' + field);
                const statusSpan = document.getElementById('status-' + field);

                modeInput.value = newMode;
                ['static', 'file', 'url'].forEach(m => {
                    const btn = document.getElementById('btn-' + m + '-' + field);
                    if (btn) btn.className = "mode-btn " + (m === newMode ? "active" : "");
                });

                if (toggleContainer) {
                    if (newMode === 'static') {
                        toggleContainer.classList.remove('hidden');
                        inputField.classList.add('hidden');
                        
                        if (field === 'DI') {
                            let val = parseInt(inputField.value) || 0;
                            document.getElementById('di-cb-1').checked = (val & 1) !== 0;
                            document.getElementById('di-cb-2').checked = (val & 2) !== 0;
                            document.getElementById('di-cb-4').checked = (val & 4) !== 0;
                            document.getElementById('di-cb-8').checked = (val & 8) !== 0;
                            if (document.getElementById('di-val-display')) {
                                document.getElementById('di-val-display').innerText = val;
                            }
                        } else {
                            const isChecked = inputField.value === '1' || inputField.value.toUpperCase() === 'ON' || inputField.value.toUpperCase() === 'M';
                            const offLabel = statusSpan.dataset.off;
                            const onLabel = statusSpan.dataset.on;
                            
                            document.getElementById('checkbox-' + field).checked = isChecked;
                            statusSpan.innerText = isChecked ? onLabel : offLabel;
                            statusSpan.className = isChecked ? 'toggle-text active' : 'toggle-text';
                        }
                    } else {
                        toggleContainer.classList.add('hidden');
                        inputField.classList.remove('hidden');
                        inputField.placeholder = newMode === 'file' ? "/path/to/data.txt" : "https://example.com/api/rds";
                    }
                } else {
                    if(newMode === 'static') inputField.placeholder = inputField.dataset.staticPlaceholder;
                    else if(newMode === 'file') inputField.placeholder = "/path/to/data.txt";
                    else inputField.placeholder = "https://example.com/api/rds";
                }
            }
            
            function openSettings() { 
                const modal = document.getElementById('settingsModal');
                const card = document.getElementById('settingsCard');
                modal.classList.add('show');
                setTimeout(() => { card.classList.add('show'); }, 10);
            }
            
            function closeSettings() { 
                const modal = document.getElementById('settingsModal');
                const card = document.getElementById('settingsCard');
                card.classList.remove('show');
                setTimeout(() => { modal.classList.remove('show'); }, 300);
            }

            // --- AF List Management ---
            let afFrequencies = [${afList.map(f => `'${f}'`).join(',')}];

            function renderAF() {
                const container = document.getElementById('af-container');
                if(afFrequencies.length === 0) {
                    container.innerHTML = '<span class="af-empty">No alternative frequencies saved</span>';
                } else {
                    container.innerHTML = afFrequencies.map((freq, index) => \`
                        <div class="af-tag" onclick="removeAF(event, \${index})">
                            <span>\${freq}</span>
                            <div class="af-tag-icon">
                                <i data-lucide="x" class="w-4 h-4"></i>
                            </div>
                        </div>
                    \`).join('');
                    lucide.createIcons();
                }
                
                // Keep the hidden input updated so it saves upon 'Apply Changes'
                const hiddenInput = document.getElementById('input-AF');
                if(hiddenInput) hiddenInput.value = afFrequencies.join(' ');
            }

            function addAF() {
                const input = document.getElementById('af-input');
                const val = input.value.trim().replace(',', '.');
                
                if(val && !afFrequencies.includes(val) && !isNaN(parseFloat(val))) {
                    afFrequencies.push(val);
                    input.value = '';
                    renderAF(); 
                } else {
                    input.value = ''; 
                }
            }

            function removeAF(event, index) {
                if (event) event.stopPropagation();
                afFrequencies.splice(index, 1);
                renderAF();
            }

            function clearAF() {
                afFrequencies = [];
                renderAF();
            }

            document.getElementById('af-input').addEventListener('keypress', function(e) {
                if(e.key === 'Enter') {
                    e.preventDefault();
                    addAF();
                }
            });

            renderAF();
        </script>
    </body>
    </html>`;
}

app.listen(PORT, '0.0.0.0', () => console.log(`🚀 NanoRDS running at http://0.0.0.0:${PORT}`));