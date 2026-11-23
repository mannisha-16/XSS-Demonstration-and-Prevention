// DOM-Based XSS - Protected Implementation (Phase 2)
// Read data from the URL parameter
const params = new URLSearchParams(window.location.search);
const message = params.get("message") || "";

// Find the output area
const output = document.getElementById("output");

if (output && message) {
    // SECURE FIX: Using textContent treats the input strictly as a plain text node!
    // The browser's HTML parser is completely bypassed.
    output.style.padding = "10px 14px";
    output.style.backgroundColor = "#fafbfc";
    output.style.border = "1px solid #d0d7de";
    output.style.borderRadius = "4px";

    const label = document.createElement("div");
    label.style.fontWeight = "bold";
    label.style.marginBottom = "5px";
    label.style.color = "#0b3c5d";
    label.textContent = "Safe Text Node Rendered by textContent:";

    const contentDiv = document.createElement("div");
    contentDiv.style.fontFamily = "Consolas, monospace";
    contentDiv.style.fontSize = "13px";
    contentDiv.style.color = "#333";
    contentDiv.style.wordBreak = "break-all";

    // Safe assignment:
    contentDiv.textContent = message;

    output.appendChild(label);
    output.appendChild(contentDiv);
}
