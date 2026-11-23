// DOM-Based XSS - Vulnerable Implementation
// Flow: URL parameter (?message=...) -> Client JavaScript -> DOM sink (innerHTML)

const params = new URLSearchParams(window.location.search);
const message = params.get("message") || "";

// DOM Elements
const output = document.getElementById("output");
const heading = document.getElementById("dom-page-heading");
const statusBox = document.getElementById("dom-sample-status-box");
const statusTitle = document.getElementById("dom-sample-status-title");
const statusText = document.getElementById("dom-sample-status-text");
const statusBadge = document.getElementById("dom-status-badge");
const alertBanner = document.getElementById("dom-alert-banner-container");

// Reusable DOM defacement trigger
function applyDomDefacement() {
    if (alertBanner) alertBanner.style.display = "block";
    if (heading) heading.innerText = "⚠️ DEFACED: Student Portal Tampered via DOM XSS";
    if (statusBadge) {
        statusBadge.className = "status-badge status-compromised";
        statusBadge.innerText = "▲ CRITICAL COMPROMISE";
    }
    if (statusTitle) statusTitle.innerText = "System Status: CRITICAL COMPROMISE";
    if (statusText) statusText.innerText = "Workstation network disabled by client-side DOM injection.";
    if (statusBox) statusBox.className = "sample-portal-box defaced-card";
}

// Make accessible for inline event handlers (e.g., onerror="triggerDomDefacement()")
window.triggerDomDefacement = applyDomDefacement;

if (output && message) {
    // VULNERABLE SINK: Directly assigns untrusted input to innerHTML
    output.innerHTML = message;

    // Execute any script tags dynamically if present (for browsers that don't auto-eval innerHTML scripts)
    const scripts = output.getElementsByTagName("script");
    for (let i = 0; i < scripts.length; i++) {
        const newScript = document.createElement("script");
        newScript.textContent = scripts[i].textContent;
        document.body.appendChild(newScript);
    }

    // Check if the input is a simulated defacement payload
    const isDefacing = /DEFACED|CRITICAL COMPROMISE|SECURITY ALERT|WARNING|ALERT|modified|tamper|<script|<img|<div style|alert\(/i.test(message);

    if (isDefacing) {
        applyDomDefacement();
    }
}
