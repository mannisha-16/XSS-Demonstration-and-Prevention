/**
 * XSS Demonstration and Prevention Project
 * BTech Cybersecurity Semester Project
 * 
 * Features:
 * - Full-width professional security alert banners (No JavaScript popup alerts)
 * - Visible website content compromise simulations with CIA triad impact analysis
 * - Reflected XSS: "SECURITY ALERT — WEBSITE COMPROMISED"
 * - Stored XSS: "STORED XSS ATTACK — WEBSITE CONTENT COMPROMISED" (Single-Page Workflow)
 * - DOM-Based XSS: "DOM-BASED XSS — PAGE CONTENT MODIFIED"
 * - Phase 2 Defense-in-Depth Prevention (Output Encoding, textContent, CSP, Validation)
 * - Final Navigation: Home, Reflected XSS, Stored XSS, DOM-Based XSS, Prevention System
 */

const express = require("express");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = 3000;
const DATA_FILE = path.join(__dirname, "data", "comments.json");

// Default clean comments for demonstration reset
const DEFAULT_COMMENTS = [
    {
        id: 101,
        author: "Campus Administrator",
        comment: "Welcome to the College Project Portal. All academic systems and server nodes are operating normally.",
        createdAt: "01/11/2026, 09:00:00 am"
    },
    {
        id: 102,
        author: "Academic Office",
        comment: "Please submit semester project feedback and laboratory queries using this comment board.",
        createdAt: "01/11/2026, 09:15:00 am"
    }
];

// Middleware to parse form data and JSON
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Serve static frontend files without intercepting root index
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// ============================================================================
// SECURITY HELPER FUNCTIONS
// ============================================================================

/**
 * Context-Aware Output Encoding for HTML Body Context
 * Converts special characters into safe HTML entities so browsers render
 * them strictly as text rather than executable markup.
 */
function escapeHTML(str) {
    if (typeof str !== "string") return "";
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#x27;")
        .replace(/\//g, "&#x2F;");
}

/**
 * Server-Side Input Validation
 * Validates length, data type, and rejects empty submissions or control characters.
 */
function validateComment(comment) {
    if (typeof comment !== "string") {
        return { valid: false, error: "Comment must be a text string." };
    }
    const trimmed = comment.trim();
    if (trimmed.length < 1) {
        return { valid: false, error: "Comment cannot be empty." };
    }
    if (trimmed.length > 500) {
        return { valid: false, error: "Comment exceeds maximum limit of 500 characters." };
    }
    if (/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(comment)) {
        return { valid: false, error: "Comment contains illegal control characters." };
    }
    return { valid: true, sanitized: trimmed };
}

/**
 * Content Security Policy (CSP) and Defense HTTP Headers
 */
function setSecurityHeaders(res) {
    res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self';"
    );
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "SAMEORIGIN");
}

/**
 * Load comments from database
 */
function loadComments() {
    try {
        if (!fs.existsSync(DATA_FILE)) {
            saveComments(DEFAULT_COMMENTS);
            return DEFAULT_COMMENTS;
        }
        const data = fs.readFileSync(DATA_FILE, "utf8");
        const parsed = JSON.parse(data);
        return Array.isArray(parsed) ? parsed : DEFAULT_COMMENTS;
    } catch (error) {
        console.error("Error reading database:", error.message);
        return DEFAULT_COMMENTS;
    }
}

/**
 * Save comments to database
 */
function saveComments(comments) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(comments, null, 2), "utf8");
}

// ============================================================================
// COMMON REUSABLE COMPONENTS
// ============================================================================

/**
 * Reusable Main Navigation Bar (5 Items per Section 9)
 * 1. Home
 * 2. Reflected XSS
 * 3. Stored XSS
 * 4. DOM-Based XSS
 * 5. Prevention System
 */
function getNavBar(activeItem = "home") {
    return `
    <nav>
        <div class="nav-content">
            <a href="/" class="${activeItem === 'home' ? 'active' : ''}">Home</a>
            <a href="/reflected-vulnerable" class="${activeItem === 'reflected' ? 'active' : ''}">Reflected XSS</a>
            <a href="/comments-vulnerable" class="${activeItem === 'stored' ? 'active' : ''}">Stored XSS</a>
            <a href="/dom-demo" class="${activeItem === 'dom' ? 'active' : ''}">DOM-Based XSS</a>
            <a href="/prevention" class="${activeItem === 'prevention' ? 'active' : ''}">Prevention System</a>
        </div>
    </nav>
    `;
}

/**
 * Reusable Security Alert Banner Component (Section 6)
 * Generates a full-width red warning banner with dark red heading, warning icon,
 * attack type badge, simulation-only badge, compromise description, and CIA impact points.
 */
function renderSecurityAlertBanner({
    attackType,
    heading,
    description,
    impacts,
    resetUrl = null,
    resetLabel = "Restore Original Page",
    protectedUrl = null
}) {
    return `
    <div class="security-compromise-banner" id="security-alert-banner">
        <div class="banner-header">
            <span class="banner-icon">⚠️</span>
            <div class="banner-title-group">
                <div class="banner-tags">
                    <span class="attack-type-badge">${escapeHTML(attackType)}</span>
                    <span class="simulation-badge">SIMULATION ONLY</span>
                </div>
                <h2 class="banner-heading">${heading}</h2>
            </div>
        </div>
        <div class="banner-body">
            <p class="banner-desc">${description}</p>
            <div class="banner-impacts-box">
                <strong>Simulated Website Impacts:</strong>
                <ul>
                    ${impacts.map(i => `<li>${i}</li>`).join("")}
                </ul>
            </div>
            <div class="cia-grid">
                <div class="cia-card compromised">
                    <strong>Confidentiality Risk</strong>
                    <span>Unauthorized script execution could read on-page DOM data, forms, and sensitive browser session tokens.</span>
                </div>
                <div class="cia-card compromised">
                    <strong>Integrity Violated</strong>
                    <span>Website content integrity has been violated: Legitimate notices altered and fake advisories injected.</span>
                </div>
                <div class="cia-card compromised">
                    <strong>Availability Disrupted</strong>
                    <span>Authentic website status and services superseded by simulated compromise alerts.</span>
                </div>
            </div>
            <div class="banner-actions">
                ${resetUrl ? `<a href="${resetUrl}" class="btn btn-warning">${resetLabel}</a>` : ""}
                ${protectedUrl ? `<a href="${protectedUrl}" class="btn btn-success">View Protected Result &rarr;</a>` : ""}
            </div>
        </div>
    </div>
    `;
}

// ============================================================================
// 1. HOME PAGE
// ============================================================================

app.get("/", (req, res) => {
    setSecurityHeaders(res);
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ============================================================================
// 2. REFLECTED XSS (VULNERABLE & PROTECTED)
// ============================================================================

// Vulnerable Reflected XSS Demonstration
app.get("/reflected-vulnerable", (req, res) => {
    const query = req.query.query || req.query.name || "";
    const isDefacing = query && (/DEFACED|CRITICAL COMPROMISE|SECURITY ALERT|WARNING|ALERT|modified|tamper|<script|<img|<div style|alert\(/i.test(query));

    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Reflected XSS - Vulnerable Demonstration</title>
            <link rel="stylesheet" href="style.css">
        </head>
        <body>
            <header>
                <div class="header-content">
                    <h1>Reflected XSS Demonstration (Vulnerable)</h1>
                    <p>BTech Cybersecurity Project | Flow: URL Query &rarr; Express Server &rarr; Unescaped HTML Stream &rarr; Browser</p>
                </div>
            </header>

            ${getNavBar("reflected")}

            <main class="container">
                <div class="box">
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 15px;">
                        <h2 style="margin: 0; border: none; padding: 0;">Reflected XSS - Visible Website Compromise</h2>
                        <div>
                            <span class="badge-fail" style="font-size: 13px; padding: 5px 10px;">VULNERABLE DEMONSTRATION</span>
                            <a href="/reflected-secure" class="btn btn-success" style="font-size: 12px; margin-left: 8px;">View Protected Demo &rarr;</a>
                        </div>
                    </div>

                    <p>
                        In Reflected XSS, the web server takes untrusted data from the URL query parameter and directly echoes it
                        into the HTML response stream without context-appropriate output encoding.
                    </p>

                    <!-- REUSABLE FULL-WIDTH SECURITY ALERT BANNER (Shown when vulnerable input is executed) -->
                    ${isDefacing ? renderSecurityAlertBanner({
                        attackType: "Reflected XSS",
                        heading: "SECURITY ALERT — WEBSITE COMPROMISED",
                        description: "Unauthorized JavaScript/HTML execution has modified the website! Untrusted input from the URL query parameter was reflected unescaped by the web server, violating website content integrity.",
                        impacts: [
                            "Unauthorized Website Content Modification: Department notice board heading and official notices were overwritten.",
                            "System Status Tampered: Changed from 'System Operational' to 'CRITICAL COMPROMISE'.",
                            "Reflected Delivery Vector: Malicious payload was delivered through the HTTP request query parameter.",
                            "Content Integrity Violated: Visitors clicking this crafted link observe defaced academic notices."
                        ],
                        resetUrl: "/reflected-vulnerable",
                        resetLabel: "Restore Original Page",
                        protectedUrl: "/reflected-secure"
                    }) : ""}

                    <!-- DUMMY WEBSITE COMPONENT: Department Notice Board -->
                    <div id="sample-dept-announcement" class="sample-portal-box ${isDefacing ? 'defaced-card' : 'sample-portal-blue'}">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <strong style="color: ${isDefacing ? '#c62828' : '#0b3c5d'}; font-size: 14px;">
                                Sample Website: Department of Computer Science &amp; Engineering
                            </strong>
                            <span class="status-badge ${isDefacing ? 'status-compromised' : 'status-operational'}">
                                ${isDefacing ? '▲ CRITICAL COMPROMISE' : '● System Operational'}
                            </span>
                        </div>
                        <h3 id="sample-dept-heading" style="margin: 4px 0 8px 0; color: ${isDefacing ? '#c62828' : '#0b3c5d'}; font-size: 18px;">
                            ${isDefacing 
                                ? '⚠️ DEFACED: Department Notice Board Compromised' 
                                : 'Department of Computer Science - Official Notice Board'}
                        </h3>
                        <p id="dept-notice-text" style="margin: 0; color: ${isDefacing ? '#b71c1c' : '#333'}; font-size: 14px;">
                            ${isDefacing 
                                ? 'Notice: Normal academic operations have been suspended due to an unauthorized simulated defacement.' 
                                : 'Campus cafeteria and student transport facilities are operating on regular schedule.'}
                        </p>
                    </div>

                    <!-- Input Form -->
                    <form method="GET" action="/reflected-vulnerable">
                        <div class="form-group">
                            <label for="query-input">Submit Search or Notice Query (Vulnerable Reflection):</label>
                            <input type="text" id="query-input" name="query" value="${query.replace(/"/g, '&quot;')}" placeholder="Enter query or select a preset demonstration payload below..." required>
                        </div>
                        <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                            <button type="submit" class="btn btn-danger">Submit Query (Vulnerable Echo)</button>
                            <a href="/reflected-vulnerable" class="btn btn-warning">Restore Original Page</a>
                        </div>
                    </form>

                    <!-- Reflected Output Area (Unescaped Stream) -->
                    ${query ? `
                        <div style="margin-top: 20px; padding: 14px; background-color: #fff8f8; border: 1px solid #ffcdd2; border-radius: 4px;">
                            <strong style="color: #c62828;">Server Response (Reflected Directly Without Output Encoding):</strong>
                            <div style="margin: 6px 0; padding: 8px; background: #fff; border: 1px solid #ffcdd2; border-radius: 3px;">
                                Search result: ${query}
                            </div>
                            <div style="font-size: 13px; color: #c62828;">
                                <span class="badge-fail">VULNERABLE</span> Server echoed raw input into HTML stream. Browser parsed tags as executable markup.
                            </div>
                        </div>
                    ` : ""}

                    <!-- Before-and-After Comparison View -->
                    <h3 style="margin-top: 25px;">Before Attack vs After Simulation Comparison</h3>
                    <div class="comparison-grid">
                        <div class="comparison-col comparison-before">
                            <strong style="color: #2e7d32;">Original State (Before Attack)</strong>
                            <p style="margin: 5px 0 0 0;">Status: <span class="status-badge status-operational">● System Operational</span></p>
                            <p style="margin: 4px 0 0 0;">Heading: <em>"Department of Computer Science - Official Notice Board"</em></p>
                            <p style="margin: 4px 0 0 0; color: #555;">Legitimate notice displayed; zero warning banners.</p>
                        </div>
                        <div class="comparison-col comparison-after">
                            <strong style="color: #c62828;">Compromised State (After Attack)</strong>
                            <p style="margin: 5px 0 0 0;">Status: <span class="status-badge status-compromised">▲ CRITICAL COMPROMISE</span></p>
                            <p style="margin: 4px 0 0 0;">Heading: <em>"⚠️ DEFACED: Department Notice Board Compromised"</em></p>
                            <p style="margin: 4px 0 0 0; color: #555;">Full-width security banner displayed; content integrity violated.</p>
                        </div>
                    </div>

                    <!-- Preset Demonstration Payloads -->
                    <h3>Select Controlled Demonstration Payloads:</h3>
                    <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px;">
                        <a href="/reflected-vulnerable?query=Computer+Science+Syllabus" class="btn btn-secondary">Safe Query</a>
                        <a href="/reflected-vulnerable?query=%3Cscript%3Edocument.getElementById('sample-dept-heading').innerText%3D'%E2%9A%A0%EF%B8%8F+DEFACED%3A+Department+Notice+Board+Compromised'%3B+document.getElementById('dept-notice-text').innerText%3D'Notice%3A+Normal+academic+operations+suspended+via+Reflected+XSS!'%3B+document.getElementById('sample-dept-announcement').className%3D'sample-portal-box+defaced-card'%3B%3C%2Fscript%3E" class="btn btn-danger">
                            Execute Heading &amp; Content Defacement Payload
                        </a>
                        <a href="/reflected-vulnerable?query=%3Cdiv+class%3D%22alert+alert-warning%22+style%3D%22border%3A2px+solid+%23856404%3Bmargin%3A10px+0%3B%22%3E%3Cstrong%3E%E2%9A%A0%EF%B8%8F+Website+content+has+been+modified.%3C%2Fstrong%3E+Injected+fake+security+alert.%3C%2Fdiv%3E" class="btn btn-danger">
                            Execute Injected Banner Payload
                        </a>
                    </div>
                </div>
            </main>

            <footer>
                <p>XSS Demonstration and Prevention | BTech Cybersecurity Semester Project</p>
            </footer>
        </body>
        </html>
    `);
});

// Protected Reflected XSS Implementation (Phase 2)
app.get("/reflected-secure", (req, res) => {
    setSecurityHeaders(res);

    const query = req.query.query || req.query.name || "";
    const encodedQuery = escapeHTML(query);

    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Reflected XSS - Protected Implementation</title>
            <link rel="stylesheet" href="style.css">
        </head>
        <body>
            <header>
                <div class="header-content">
                    <h1>Reflected XSS (Protected Implementation)</h1>
                    <p>BTech Cybersecurity Project | Phase 2: Context-Aware Output Encoding &amp; CSP</p>
                </div>
            </header>

            ${getNavBar("prevention")}

            <main class="container">
                <div class="box">
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 15px;">
                        <h2 style="margin: 0; border: none; padding: 0;">Reflected XSS - Output Encoding Protection</h2>
                        <div>
                            <span class="status-badge status-protected">🛡️ PROTECTED</span>
                            <a href="/reflected-vulnerable" class="btn btn-danger" style="font-size: 12px; margin-left: 8px;">View Vulnerable Demo &rarr;</a>
                        </div>
                    </div>

                    <p>
                        In this protected implementation, user-submitted search queries are processed using 
                        <strong>context-appropriate output encoding</strong> (<code>escapeHTML</code>) and defended by 
                        <strong>Content Security Policy (CSP)</strong>. Untrusted inputs cannot execute scripts or modify website content.
                    </p>

                    <!-- DUMMY WEBSITE COMPONENT: Preserved Original Notice Board -->
                    <div id="sample-dept-announcement" class="sample-portal-box sample-portal-blue">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <strong style="color: #0b3c5d; font-size: 14px;">
                                Sample Website: Department of Computer Science &amp; Engineering
                            </strong>
                            <span class="status-badge status-operational">
                                ● System Operational (Protected)
                            </span>
                        </div>
                        <h3 id="sample-dept-heading" style="margin: 4px 0 8px 0; color: #0b3c5d; font-size: 18px;">
                            Department of Computer Science - Official Notice Board
                        </h3>
                        <p id="dept-notice-text" style="margin: 0; color: #333; font-size: 14px;">
                            Campus cafeteria and student transport facilities are operating on regular schedule.
                        </p>
                    </div>

                    <!-- Input Form -->
                    <form method="GET" action="/reflected-secure">
                        <div class="form-group">
                            <label for="query-input">Submit Search or Notice Query (Protected):</label>
                            <input type="text" id="query-input" name="query" value="${encodedQuery}" placeholder="Enter query or test a malicious payload..." required>
                        </div>
                        <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                            <button type="submit" class="btn btn-success">Search Safely</button>
                            <a href="/reflected-secure" class="btn btn-warning">Restore Original Page</a>
                        </div>
                    </form>

                    <!-- Safe Output Display -->
                    ${query ? `
                        <div style="margin-top: 20px; padding: 14px; background-color: #fafbfc; border: 1px solid #d0d7de; border-radius: 4px;">
                            <strong>Server Reflected Response (Safely Encoded as Text):</strong>
                            <p style="margin: 6px 0; font-family: Consolas, monospace; background: #fff; padding: 8px; border: 1px solid #e1e4e8; border-radius: 3px; word-break: break-all;">
                                Search result: ${encodedQuery}
                            </p>
                            <div style="font-size: 13px; color: #2e7d32;">
                                <span class="badge-pass">PASS</span> Characters safely converted to HTML entities. Website heading and notice board remain 100% intact; zero script execution.
                            </div>
                        </div>
                    ` : ""}

                    <!-- Prevention Comparison View (Side-by-Side) -->
                    <h3 style="margin-top: 25px;">Vulnerable vs Protected Outcome Comparison</h3>
                    <div class="comparison-grid">
                        <div class="comparison-col comparison-after">
                            <strong style="color: #c62828;">Vulnerable Demonstration</strong>
                            <p style="margin: 5px 0 0 0;">Status: <span class="status-badge status-compromised">▲ CRITICAL COMPROMISE</span></p>
                            <p style="margin: 4px 0 0 0; color: #555;">Server echoes raw unescaped input into HTML. Untrusted markup triggers "SECURITY ALERT — WEBSITE COMPROMISED", defaces notice, and violates integrity.</p>
                        </div>
                        <div class="comparison-col comparison-before">
                            <strong style="color: #2e7d32;">Protected Demonstration</strong>
                            <p style="margin: 5px 0 0 0;">Status: <span class="status-badge status-operational">● System Operational</span></p>
                            <p style="margin: 4px 0 0 0; color: #555;">Server encodes characters (<code>escapeHTML</code>). Input is rendered strictly as harmless text with zero unwanted page modification.</p>
                        </div>
                    </div>

                    <!-- Test Same Payloads Against Protected Endpoint -->
                    <h3>Test Payloads Against Protected Endpoint:</h3>
                    <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px;">
                        <a href="/reflected-secure?query=Computer+Science+Syllabus" class="btn btn-secondary">Safe Query</a>
                        <a href="/reflected-secure?query=%3Cscript%3Edocument.getElementById('sample-dept-heading').innerText%3D'%E2%9A%A0%EF%B8%8F+DEFACED%3A+Department+Notice+Board+Compromised'%3B+document.getElementById('dept-notice-text').innerText%3D'Notice%3A+Normal+academic+operations+suspended+via+Reflected+XSS!'%3B+document.getElementById('sample-dept-announcement').className%3D'sample-portal-box+defaced-card'%3B%3C%2Fscript%3E" class="btn btn-secondary">
                            Test Defacement Payload
                        </a>
                        <a href="/reflected-secure?query=%3Cdiv+class%3D%22alert+alert-warning%22+style%3D%22border%3A2px+solid+%23856404%3Bmargin%3A10px+0%3B%22%3E%3Cstrong%3E%E2%9A%A0%EF%B8%8F+Website+content+has+been+modified.%3C%2Fstrong%3E%3C%2Fdiv%3E" class="btn btn-secondary">
                            Test Warning Banner Payload
                        </a>
                    </div>
                </div>
            </main>

            <footer>
                <p>XSS Demonstration and Prevention | BTech Cybersecurity Semester Project</p>
            </footer>
        </body>
        </html>
    `);
});

// ============================================================================
// 3. STORED XSS (SINGLE-PAGE WORKFLOW ONLY - SECTION 3)
// ============================================================================

// Single-Page Vulnerable Stored XSS Demonstration
app.get("/comments-vulnerable", (req, res) => {
    const comments = loadComments();

    // Check if database contains an active demonstration payload
    const hasDefacement = comments.some(c => /DEFACED|CRITICAL COMPROMISE|SECURITY ALERT|STORED XSS ATTACK|alert\(|tamper|<script|<img|<div style/i.test(c.comment));

    const commentHTML = comments
        .map(item => `
            <div class="comment-item" style="border-left-color: #c62828;">
                <div class="comment-meta">
                    <strong>ID: ${item.id} ${item.author ? `| ${escapeHTML(item.author)}` : ""}</strong>
                    <small>${item.createdAt}</small>
                </div>
                <!-- VULNERABLE: Direct HTML concatenation without escaping -->
                <div class="comment-text">
                    ${item.comment}
                </div>
            </div>
        `)
        .join("");

    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Stored XSS - Vulnerable Demonstration (Single-Page Workflow)</title>
            <link rel="stylesheet" href="style.css">
        </head>
        <body>
            <header>
                <div class="header-content">
                    <h1>Stored XSS Demonstration (Vulnerable)</h1>
                    <p>BTech Cybersecurity Project | Single-Page Workflow: Enter Payload &rarr; Submit &rarr; Save in JSON &rarr; Render &rarr; Observe Impact</p>
                </div>
            </header>

            ${getNavBar("stored")}

            <main class="container">
                <div class="box">
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 15px;">
                        <h2 style="margin: 0; border: none; padding: 0;">Stored XSS - Persistent Content Modification</h2>
                        <div>
                            <span class="badge-fail" style="font-size: 13px; padding: 5px 10px;">VULNERABLE DEMONSTRATION</span>
                            <a href="/stored-secure" class="btn btn-success" style="font-size: 12px; margin-left: 8px;">View Protected Demo &rarr;</a>
                        </div>
                    </div>

                    <p>
                        This demonstration illustrates the impact of <strong>Stored Cross-Site Scripting (XSS)</strong> on a single page.
                        When comments are saved into permanent JSON storage without validation or encoding, the stored content is rendered
                        as raw executable markup every time this page is loaded or refreshed.
                    </p>

                    <!-- REUSABLE FULL-WIDTH SECURITY ALERT BANNER (Shown when stored payload is active) -->
                    ${hasDefacement ? renderSecurityAlertBanner({
                        attackType: "Stored XSS (Persistent)",
                        heading: "STORED XSS ATTACK — WEBSITE CONTENT COMPROMISED",
                        description: "A demonstration payload stored in the JSON database has executed on this page! Because stored content is rendered directly as unescaped HTML, the page heading, announcement, and system status have been modified.",
                        impacts: [
                            "Persistent Content Tampering: Legitimate examination announcement replaced with unauthorized defacement notice.",
                            "System Status Tampered: Changed from 'System Operational' to 'CRITICAL COMPROMISE'.",
                            "Persistence Across Refreshes: Try refreshing this page (F5) — the simulated compromise remains active because it is saved in comments.json!",
                            "Integrity Compromised: Any visitor who opens this page executes the stored payload automatically."
                        ],
                        resetUrl: null, // Will use dedicated reset form button below
                        protectedUrl: "/stored-secure"
                    }) : ""}

                    <!-- DUMMY WEBSITE COMPONENT: College Portal Announcement -->
                    <div id="sample-portal-announcement" class="sample-portal-box ${hasDefacement ? 'defaced-card' : 'sample-portal-normal'}">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <strong style="color: ${hasDefacement ? '#c62828' : '#2e7d32'}; font-size: 14px;">
                                Sample Website: College Project Portal Announcement
                            </strong>
                            <span class="status-badge ${hasDefacement ? 'status-compromised' : 'status-operational'}">
                                ${hasDefacement ? '▲ CRITICAL COMPROMISE' : '● System Operational'}
                            </span>
                        </div>
                        <h3 id="portal-notice-heading" style="margin: 4px 0 8px 0; color: ${hasDefacement ? '#c62828' : '#0b3c5d'}; font-size: 18px;">
                            ${hasDefacement 
                                ? '⚠️ DEFACED: College Portal Announcement Tampered via Stored XSS' 
                                : 'College Portal Official Announcements'}
                        </h3>
                        <p id="portal-notice-text" style="margin: 0; color: ${hasDefacement ? '#b71c1c' : '#333'}; font-size: 14px;">
                            ${hasDefacement 
                                ? 'Notice: All examinations cancelled and departmental servers taken offline due to stored payload execution.' 
                                : 'Semester examinations commence next Monday. All departmental computer labs and web servers are operational.'}
                        </p>
                    </div>

                    <!-- Single-Page Comment Submission Form -->
                    <form method="POST" action="/comments" style="margin-top: 20px;">
                        <div class="form-group">
                            <label for="comment-input">Submit Comment or Announcement (Vulnerable Direct JSON Storage):</label>
                            <textarea id="comment-input" name="comment" placeholder="Enter a normal comment or select a preset demonstration payload below..." required></textarea>
                        </div>
                        <div style="display: flex; gap: 10px; flex-wrap: wrap; align-items: center;">
                            <button type="submit" class="btn btn-danger">Submit Comment (Save in JSON &amp; Render)</button>
                        </div>
                    </form>

                    <!-- Quick Preset Impact Buttons -->
                    <h4 style="margin-top: 18px; margin-bottom: 8px;">Click to Load Demonstration Payloads into Form:</h4>
                    <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px;">
                        <button type="button" class="btn btn-secondary" onclick="loadStoredPayload(1)">
                            Load Payload 1: Simulate Announcement Defacement Script
                        </button>
                        <button type="button" class="btn btn-secondary" onclick="loadStoredPayload(2)">
                            Load Payload 2: Simulate Injected Security Warning Banner
                        </button>
                    </div>

                    <!-- Reset Functionality (Section 3 Requirement) -->
                    <div style="margin: 20px 0; padding: 14px; background-color: #fafbfc; border: 1px solid #d0d7de; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; border-radius: 4px;">
                        <div>
                            <strong>Reset Demonstration:</strong> Removes stored demonstration comments, restores original announcement, changes status back to "System Operational", and clears the security banner.
                        </div>
                        <form method="POST" action="/reset-comments" style="margin:0;">
                            <button type="submit" class="btn btn-warning">Reset Stored Demonstration</button>
                        </form>
                    </div>

                    <!-- Stored Database Comments Rendered on Same Page -->
                    <h3 style="margin-top: 25px;">Stored Database Comments (${comments.length})</h3>
                    <p style="font-size: 13px; color: #555;">
                        Comments below are read directly from <code>comments.json</code> and rendered into this page without output escaping:
                    </p>
                    <div>
                        ${commentHTML || "<p style='color: #777;'>No comments stored yet.</p>"}
                    </div>
                </div>
            </main>

            <footer>
                <p>XSS Demonstration and Prevention | BTech Cybersecurity Semester Project</p>
            </footer>

            <script>
                function loadStoredPayload(type) {
                    const txt = document.getElementById('comment-input');
                    if (!txt) return;
                    if (type === 1) {
                        txt.value = '<script>document.getElementById("portal-notice-heading").innerText = "⚠️ DEFACED: College Portal Announcement Tampered via Stored XSS"; document.getElementById("portal-notice-text").innerText = "Notice: All examinations cancelled and departmental servers taken offline due to stored payload execution."; document.getElementById("sample-portal-announcement").className = "sample-portal-box defaced-card";<\\/script>';
                    } else if (type === 2) {
                        txt.value = '<div class="alert alert-warning" style="border:2px solid #856404;margin:10px 0;"><strong>⚠️ Unauthorized Content Modification:</strong> Critical security warning injected into stored comments database.</div>';
                    }
                }
            </script>
        </body>
        </html>
    `);
});

// Vulnerable Comment Submission Endpoint (Saves and redirects back to same page)
app.post("/comments", (req, res) => {
    const comment = req.body.comment || "";
    const comments = loadComments();

    // Vulnerable pipeline: no sanitization, stored raw in JSON
    comments.push({
        id: Date.now(),
        author: "User",
        comment: comment,
        createdAt: new Date().toLocaleString()
    });
    saveComments(comments);

    // Redirect to the same page so user observes the stored impact immediately
    res.redirect("/comments-vulnerable");
});

// Single-Page Protected Stored XSS Implementation (Phase 2)
app.get("/stored-secure", (req, res) => {
    setSecurityHeaders(res);
    const comments = loadComments();

    const commentHTML = comments
        .map(item => `
            <div class="comment-item">
                <div class="comment-meta">
                    <strong>ID: ${item.id} ${item.author ? `| ${escapeHTML(item.author)}` : ""}</strong>
                    <div>
                        <span class="badge-safe">Rendered as Safe Text</span>
                        <small style="margin-left: 8px;">${escapeHTML(item.createdAt || "")}</small>
                    </div>
                </div>
                <!-- PROTECTED: Safe output encoding prevents script execution -->
                <div class="comment-text">
                    ${escapeHTML(item.comment)}
                </div>
            </div>
        `)
        .join("");

    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Stored XSS - Protected Implementation</title>
            <link rel="stylesheet" href="style.css">
        </head>
        <body>
            <header>
                <div class="header-content">
                    <h1>Stored XSS (Protected Implementation)</h1>
                    <p>BTech Cybersecurity Project | Phase 2: Server Input Validation &amp; Safe Output Rendering</p>
                </div>
            </header>

            ${getNavBar("prevention")}

            <main class="container">
                <div class="box">
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 15px;">
                        <h2 style="margin: 0; border: none; padding: 0;">Stored XSS - Protected Comment Board</h2>
                        <div>
                            <span class="status-badge status-protected">🛡️ PROTECTED</span>
                            <a href="/comments-vulnerable" class="btn btn-danger" style="font-size: 12px; margin-left: 8px;">View Vulnerable Demo &rarr;</a>
                        </div>
                    </div>

                    <p>
                        In this protected implementation, submitted comments are validated on the server side before storage,
                        and rendered using <strong>context-aware output encoding</strong> and <strong>safe DOM APIs (<code>textContent</code>)</strong>.
                        Even if malicious script payloads are submitted, they are displayed strictly as harmless text characters without modifying the announcement or website status.
                    </p>

                    <!-- DUMMY WEBSITE COMPONENT: Preserved Original Portal Announcement -->
                    <div id="sample-portal-announcement" class="sample-portal-box sample-portal-normal">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <strong style="color: #2e7d32; font-size: 14px;">
                                Sample Website: College Project Portal Announcement
                            </strong>
                            <span class="status-badge status-operational">
                                ● System Operational (Protected)
                            </span>
                        </div>
                        <h3 id="portal-notice-heading" style="margin: 4px 0 8px 0; color: #0b3c5d; font-size: 18px;">
                            College Portal Official Announcements
                        </h3>
                        <p id="portal-notice-text" style="margin: 0; color: #333; font-size: 14px;">
                            Semester examinations commence next Monday. All departmental computer labs and web servers are operational.
                        </p>
                    </div>

                    <!-- Protected Submission Form -->
                    <form method="POST" action="/submit-comment" style="margin-top: 20px;">
                        <div class="form-group">
                            <label for="comment-input">Submit Comment (Protected Pipeline with Server Validation):</label>
                            <textarea id="comment-input" name="comment" placeholder="Enter normal comment or test an XSS payload like <script>alert(1)</script>..." required></textarea>
                            <div class="hint">Server validates input length (1-500 chars) and rejects empty or control characters.</div>
                        </div>
                        <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                            <button type="submit" class="btn btn-primary">Submit Comment Safely</button>
                        </div>
                    </form>

                    <!-- Reset Demonstration Option -->
                    <div style="margin: 20px 0; padding: 14px; background-color: #fafbfc; border: 1px solid #d0d7de; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; border-radius: 4px;">
                        <div>
                            <strong>Reset Comments:</strong> Restores database comments to default clean state.
                        </div>
                        <form method="POST" action="/reset-comments" style="margin:0;">
                            <button type="submit" class="btn btn-warning">Reset Demo Comments</button>
                        </form>
                    </div>

                    <!-- Stored Database Comments Rendered Safely -->
                    <h3 style="margin-top: 25px;">Stored Database Comments (${comments.length})</h3>
                    <div>
                        ${commentHTML || "<p style='color: #777;'>No comments stored yet.</p>"}
                    </div>
                </div>
            </main>

            <footer>
                <p>XSS Demonstration and Prevention | BTech Cybersecurity Semester Project</p>
            </footer>
        </body>
        </html>
    `);
});

// Protected Comment Submission Endpoint
app.post("/submit-comment", (req, res) => {
    const rawComment = req.body.comment || "";

    const validation = validateComment(rawComment);
    if (!validation.valid) {
        return res.redirect("/stored-secure?error=" + encodeURIComponent(validation.error));
    }

    const comments = loadComments();
    comments.push({
        id: Date.now(),
        author: "User",
        comment: validation.sanitized,
        createdAt: new Date().toLocaleString()
    });
    saveComments(comments);

    res.redirect("/stored-secure?success=1");
});

// Reset Comments Endpoint (Restores clean default comments)
app.post("/reset-comments", (req, res) => {
    saveComments(DEFAULT_COMMENTS);
    const referer = req.get("Referer") || "/";
    if (referer.includes("comments-vulnerable")) {
        return res.redirect("/comments-vulnerable?reset=1");
    }
    if (referer.includes("stored-secure")) {
        return res.redirect("/stored-secure?reset=1");
    }
    res.redirect("/comments-vulnerable?reset=1");
});

app.post("/api/comments/reset", (req, res) => {
    saveComments(DEFAULT_COMMENTS);
    res.json({ success: true, comments: DEFAULT_COMMENTS });
});

app.get("/api/comments", (req, res) => {
    setSecurityHeaders(res);
    res.json(loadComments());
});

// API endpoint for security validation tests
app.post("/api/test-input", (req, res) => {
    setSecurityHeaders(res);
    const rawInput = typeof req.body.input === "string" ? req.body.input : "";

    const validation = validateComment(rawInput);
    const escaped = escapeHTML(rawInput);

    res.json({
        input: rawInput,
        valid: validation.valid,
        error: validation.error || null,
        escaped: escaped,
        length: rawInput.length
    });
});

// ============================================================================
// 4. DOM-BASED XSS (VULNERABLE & PROTECTED)
// ============================================================================

app.get("/dom-demo", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "dom-demo.html"));
});

app.get("/dom-secure", (req, res) => {
    setSecurityHeaders(res);
    res.sendFile(path.join(__dirname, "public", "dom-secure.html"));
});

// ============================================================================
// 5. PREVENTION SYSTEM HUB PAGE (SECTION 7 & 9)
// ============================================================================

app.get("/prevention", (req, res) => {
    setSecurityHeaders(res);
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>XSS Prevention System - BTech Cybersecurity</title>
            <link rel="stylesheet" href="style.css">
        </head>
        <body>
            <header>
                <div class="header-content">
                    <h1>XSS Prevention System</h1>
                    <p>BTech Cybersecurity Semester Project | Phase 2: Defense-in-Depth Mitigations</p>
                </div>
            </header>

            ${getNavBar("prevention")}

            <main class="container">
                <div class="box">
                    <h2>Phase 2: Comprehensive XSS Prevention Architecture</h2>
                    <p>
                        This section introduces the defense-in-depth mitigations implemented across all three XSS types.
                        The protected implementations demonstrate how context-appropriate output encoding, safe DOM APIs (<code>textContent</code>),
                        server-side input validation, and Content Security Policy (CSP) headers effectively neutralize attacks.
                    </p>

                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-top: 20px;">
                        <!-- Card 1 -->
                        <div class="box" style="border-top: 4px solid #2e7d32; margin: 0;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <h3>1. Reflected Prevention</h3>
                                <span class="status-badge status-protected">🛡️ PROTECTED</span>
                            </div>
                            <p style="font-size: 13px; color: #555;">
                                <strong>Applied Security Controls:</strong> Context-Aware HTML Entity Encoding (<code>escapeHTML</code>) + CSP Header.
                            </p>
                            <p style="font-size: 13px;">
                                Special characters (<code>&lt;</code>, <code>&gt;</code>, <code>&amp;</code>, <code>&quot;</code>, <code>&#39;</code>)
                                are converted into safe entities (<code>&amp;lt;script&amp;gt;</code>). The department notice board heading and "System Operational" status remain 100% intact.
                            </p>
                            <a href="/reflected-secure" class="btn btn-success" style="width: 100%; box-sizing: border-box; text-align: center;">
                                Launch Reflected Protected Demo &rarr;
                            </a>
                        </div>

                        <!-- Card 2 -->
                        <div class="box" style="border-top: 4px solid #2e7d32; margin: 0;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <h3>2. Stored Prevention</h3>
                                <span class="status-badge status-protected">🛡️ PROTECTED</span>
                            </div>
                            <p style="font-size: 13px; color: #555;">
                                <strong>Applied Security Controls:</strong> Server-Side Validation + Safe <code>textContent</code> Rendering.
                            </p>
                            <p style="font-size: 13px;">
                                Stored content is kept strictly as text data in JSON. When retrieved, it is rendered into text nodes rather than executable markup.
                                The portal announcement and "System Operational" status cannot be tampered with.
                            </p>
                            <a href="/stored-secure" class="btn btn-success" style="width: 100%; box-sizing: border-box; text-align: center;">
                                Launch Stored Protected Demo &rarr;
                            </a>
                        </div>

                        <!-- Card 3 -->
                        <div class="box" style="border-top: 4px solid #2e7d32; margin: 0;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <h3>3. DOM Prevention</h3>
                                <span class="status-badge status-protected">🛡️ PROTECTED</span>
                            </div>
                            <p style="font-size: 13px; color: #555;">
                                <strong>Applied Security Controls:</strong> Safe DOM API (<code>output.textContent = message</code>), eliminating <code>innerHTML</code>.
                            </p>
                            <p style="font-size: 13px;">
                                Untrusted URL parameters are assigned strictly to text nodes. The browser HTML parser is never invoked, preventing element creation
                                and keeping the student dashboard and system status intact.
                            </p>
                            <a href="/dom-secure" class="btn btn-success" style="width: 100%; box-sizing: border-box; text-align: center;">
                                Launch DOM Protected Demo &rarr;
                            </a>
                        </div>
                    </div>

                    <!-- Defense-in-Depth Summary Box -->
                    <div style="margin-top: 25px; padding: 16px; background-color: #fafbfc; border: 1px solid #d0d7de; border-radius: 4px;">
                        <h3 style="margin-top: 0; color: #0b3c5d;">Core Security Principles Enforced:</h3>
                        <ul style="font-size: 13px; line-height: 1.8; padding-left: 20px; margin: 0;">
                            <li><strong>Context-Appropriate Output Encoding:</strong> Ensures the browser treats data strictly as literal characters rather than code.</li>
                            <li><strong>Safe DOM Sinks:</strong> Using <code>textContent</code> instead of <code>innerHTML</code> prevents script execution in client memory.</li>
                            <li><strong>Content Security Policy (CSP):</strong> Enforces strict policy restrictions preventing unauthorized script execution.</li>
                            <li><strong>Input Validation:</strong> Validates length and data types on the backend before data touches storage.</li>
                        </ul>
                    </div>
                </div>
            </main>

            <footer>
                <p>XSS Demonstration and Prevention | BTech Cybersecurity Semester Project</p>
            </footer>
        </body>
        </html>
    `);
});

// Alias routes for Phase 1 (Demonstration) and Phase 2 (Prevention)
app.get(["/demonstration", "/phase1"], (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/phase2", (req, res) => {
    res.redirect("/prevention");
});

// ============================================================================
// SERVER INITIALIZATION
// ============================================================================

if (require.main === module) {
    app.listen(PORT, () => {
        console.log("==========================================================");
        console.log("XSS Demonstration and Prevention Project Running");
        console.log(`Phase 1 (Demonstration): http://localhost:${PORT}`);
        console.log(`Phase 2 (Prevention):    http://localhost:${PORT}/prevention`);
        console.log("==========================================================");
    });
}

module.exports = app;
