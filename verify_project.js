/**
 * Comprehensive Verification Suite for Enhanced XSS Demonstration & Prevention Project
 */
const http = require("http");
const fs = require("fs");
const path = require("path");
const app = require("./server");

const TEST_PORT = 3300;
let server;

function request(method, pathName, headers = {}, body = null) {
    return new Promise((resolve, reject) => {
        const req = http.request({
            hostname: "127.0.0.1",
            port: TEST_PORT,
            path: pathName,
            method: method,
            headers: headers
        }, (res) => {
            let data = "";
            res.on("data", chunk => { data += chunk; });
            res.on("end", () => {
                resolve({
                    statusCode: res.statusCode,
                    headers: res.headers,
                    body: data
                });
            });
        });
        req.on("error", reject);
        if (body) {
            req.write(body);
        }
        req.end();
    });
}

async function runTests() {
    console.log("=== STARTING COMPLETE XSS PROJECT VERIFICATION ===");
    let passed = 0;
    let failed = 0;

    function assert(cond, name) {
        if (cond) {
            console.log(`[PASS] ${name}`);
            passed++;
        } else {
            console.error(`[FAIL] ${name}`);
            failed++;
        }
    }

    try {
        await new Promise((resolve) => {
            server = app.listen(TEST_PORT, "127.0.0.1", () => {
                console.log(`Verification test server running on port ${TEST_PORT}`);
                resolve();
            });
        });

        // -------------------------------------------------------------
        // 1. NAVIGATION & TESTING SECTION REMOVAL (SECTIONS 8 & 9)
        // -------------------------------------------------------------
        console.log("\n--- Testing 1. 5-Item Navigation & Complete Testing Section Removal ---");
        const homeRes = await request("GET", "/");
        assert(homeRes.statusCode === 200, "Home page (/) returns 200");
        assert(homeRes.body.includes(">Home</a>"), "Navigation item 1: Home present");
        assert(homeRes.body.includes(">Reflected XSS</a>"), "Navigation item 2: Reflected XSS present");
        assert(homeRes.body.includes(">Stored XSS</a>"), "Navigation item 3: Stored XSS present");
        assert(homeRes.body.includes(">DOM-Based XSS</a>"), "Navigation item 4: DOM-Based XSS present");
        assert(homeRes.body.includes(">Prevention System</a>"), "Navigation item 5: Prevention System present");

        // Verify Testing Section was completely removed per Section 8
        assert(!homeRes.body.includes(">Testing</a>"), "Testing link removed from navigation");
        assert(!homeRes.body.includes("Part 3: Prevention Testing Section"), "Testing section card removed from homepage");
        const testRouteRes = await request("GET", "/testing");
        assert(testRouteRes.statusCode === 404, "Testing route (/testing) completely removed (returns 404)");

        // -------------------------------------------------------------
        // 2. REFLECTED XSS VULNERABLE & BANNER (SECTION 2 & 6)
        // -------------------------------------------------------------
        console.log("\n--- Testing 2. Reflected XSS Vulnerable & Full-Width Alert Banner ---");
        const cleanReflected = await request("GET", "/reflected-vulnerable");
        assert(cleanReflected.statusCode === 200, "Reflected vulnerable route returns 200");
        assert(cleanReflected.body.includes("Department of Computer Science - Official Notice Board"), "Original department heading shown before attack");
        assert(cleanReflected.body.includes("Campus cafeteria and student transport facilities are operating on regular schedule."), "Original notice content shown before attack");
        assert(cleanReflected.body.includes("● System Operational"), "Status is 'System Operational' before attack");
        assert(!cleanReflected.body.includes("SECURITY ALERT — WEBSITE COMPROMISED"), "No security alert banner before attack");

        // Execute Reflected Attack payload
        const defacePayload = encodeURIComponent("<script>document.getElementById('sample-dept-heading').innerText='⚠️ DEFACED: Department Notice Board Compromised'; document.getElementById('dept-notice-text').innerText='Notice: Normal academic operations suspended via Reflected XSS!'; document.getElementById('sample-dept-announcement').className='sample-portal-box defaced-card';</script>");
        const defacedReflected = await request("GET", `/reflected-vulnerable?query=${defacePayload}`);
        assert(defacedReflected.statusCode === 200, "Reflected defacement execution returns 200");
        assert(defacedReflected.body.includes("security-compromise-banner"), "Full-width red security alert banner container present");
        assert(defacedReflected.body.includes("SECURITY ALERT — WEBSITE COMPROMISED"), "Exact heading 'SECURITY ALERT — WEBSITE COMPROMISED' displayed");
        assert(defacedReflected.body.includes("SIMULATION ONLY"), "'SIMULATION ONLY' label present");
        assert(defacedReflected.body.includes("Reflected XSS"), "Attack type identification present");
        assert(defacedReflected.body.includes("CRITICAL COMPROMISE"), "Status modified from 'System Operational' to 'CRITICAL COMPROMISE'");
        assert(defacedReflected.body.includes("⚠️ DEFACED: Department Notice Board Compromised"), "Department heading modified to defaced notice");
        assert(defacedReflected.body.includes("Notice: Normal academic operations have been suspended due to an unauthorized simulated defacement."), "Department content modified to defaced notice");
        assert(defacedReflected.body.includes("Integrity Violated"), "Website content integrity violation warning displayed");
        assert(defacedReflected.body.includes("Restore Original Page"), "Restore Original Page button present");

        // Verify Restore button functionality
        const restoredReflected = await request("GET", "/reflected-vulnerable");
        assert(restoredReflected.body.includes("● System Operational"), "Status restored back to 'System Operational'");
        assert(restoredReflected.body.includes("Department of Computer Science - Official Notice Board"), "Original heading restored");
        assert(!restoredReflected.body.includes("SECURITY ALERT — WEBSITE COMPROMISED"), "Security alert banner removed on restore");

        // -------------------------------------------------------------
        // 3. REFLECTED XSS PROTECTED (SECTION 7)
        // -------------------------------------------------------------
        console.log("\n--- Testing 3. Reflected XSS Protected ---");
        const cleanReflectedSec = await request("GET", "/reflected-secure");
        assert(cleanReflectedSec.statusCode === 200, "Reflected secure route returns 200");
        assert(cleanReflectedSec.body.includes("PROTECTED"), "Green 'PROTECTED' indicator displayed");
        assert(cleanReflectedSec.body.includes("● System Operational"), "Status is 'System Operational'");

        const protectedReflected = await request("GET", `/reflected-secure?query=${defacePayload}`);
        assert(protectedReflected.statusCode === 200, "Protected reflected with payload returns 200");
        assert(protectedReflected.body.includes("&lt;script&gt;"), "Payload safely encoded as HTML character entities");
        assert(!protectedReflected.body.includes("<script>document.getElementById"), "Zero unescaped executable script tags generated");
        assert(protectedReflected.body.includes("● System Operational"), "Status remains 'System Operational'");
        assert(protectedReflected.body.includes("Department of Computer Science - Official Notice Board"), "Original website heading preserved 100%");
        assert(protectedReflected.body.includes("Campus cafeteria and student transport facilities are operating on regular schedule."), "Original notice content preserved 100%");
        assert(!protectedReflected.body.includes("id=\"security-alert-banner\""), "No compromise alert banner on protected page");

        // -------------------------------------------------------------
        // 4. STORED XSS SINGLE-PAGE WORKFLOW & PERSISTENCE (SECTION 3)
        // -------------------------------------------------------------
        console.log("\n--- Testing 4. Stored XSS (Single-Page Workflow Only - No User A/B) ---");
        // Reset to clean initial state
        await request("POST", "/reset-comments");

        const cleanStored = await request("GET", "/comments-vulnerable");
        assert(cleanStored.statusCode === 200, "Stored vulnerable route returns 200");
        assert(cleanStored.body.includes("Single-Page Workflow"), "Single-page workflow confirmed in header");
        assert(!cleanStored.body.includes("User A Screen"), "NO User A screen tabs or roles (removed per Section 3)");
        assert(!cleanStored.body.includes("User B Screen"), "NO User B screen tabs or roles (removed per Section 3)");
        assert(cleanStored.body.includes("College Portal Official Announcements"), "Original portal announcement heading present");
        assert(cleanStored.body.includes("● System Operational"), "Initial status is 'System Operational'");
        assert(!cleanStored.body.includes("STORED XSS ATTACK — WEBSITE CONTENT COMPROMISED"), "No alert banner in clean state");

        // Single-Page Workflow: Submit comment payload directly on same page
        console.log("Submitting stored defacement payload via POST /comments...");
        const storedPayload = "comment=" + encodeURIComponent("<script>document.getElementById('portal-notice-heading').innerText='⚠️ DEFACED: College Portal Announcement Tampered via Stored XSS';</script>");
        const submitRes = await request("POST", "/comments", {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": Buffer.byteLength(storedPayload)
        }, storedPayload);
        assert(submitRes.statusCode === 302, "Comment submission redirected back");
        assert(submitRes.headers.location === "/comments-vulnerable", "Redirected straight back to SAME page (/comments-vulnerable)");

        // Verify Simulated Impact on the Same Page
        const defacedStored = await request("GET", "/comments-vulnerable");
        assert(defacedStored.body.includes("security-compromise-banner"), "Full-width red security alert banner displayed on same page");
        assert(defacedStored.body.includes("STORED XSS ATTACK — WEBSITE CONTENT COMPROMISED"), "Exact heading 'STORED XSS ATTACK — WEBSITE CONTENT COMPROMISED' displayed");
        assert(defacedStored.body.includes("CRITICAL COMPROMISE"), "Website status changed to 'CRITICAL COMPROMISE'");
        assert(defacedStored.body.includes("⚠️ DEFACED: College Portal Announcement Tampered via Stored XSS"), "Announcement heading modified to defaced notice");
        assert(defacedStored.body.includes("Notice: All examinations cancelled and departmental servers taken offline"), "Announcement content modified to defaced notice");

        // Verify Persistence on Same Page across Page Refresh (F5)
        console.log("Simulating local page refresh (F5)...");
        const refreshedStored = await request("GET", "/comments-vulnerable");
        assert(refreshedStored.body.includes("STORED XSS ATTACK — WEBSITE CONTENT COMPROMISED"), "Simulated compromise remains visible after refreshing the same page (Persistence verified!)");
        assert(refreshedStored.body.includes("CRITICAL COMPROMISE"), "CRITICAL COMPROMISE status persists across reload");

        // Test Reset functionality (Section 3 requirement)
        console.log("Testing Reset Stored Demonstration...");
        const resetRes = await request("POST", "/reset-comments", { "Referer": "http://127.0.0.1:3300/comments-vulnerable" });
        assert(resetRes.statusCode === 302, "Reset redirected back to /comments-vulnerable");
        const afterResetStored = await request("GET", "/comments-vulnerable");
        assert(!afterResetStored.body.includes("STORED XSS ATTACK — WEBSITE CONTENT COMPROMISED"), "Security alert banner removed on reset");
        assert(afterResetStored.body.includes("● System Operational"), "Status changed back to 'System Operational'");
        assert(afterResetStored.body.includes("College Portal Official Announcements"), "Original announcement heading restored");
        assert(afterResetStored.body.includes("Semester examinations commence next Monday."), "Original announcement text restored");
        assert(afterResetStored.body.includes("Campus Administrator"), "Clean default sample comments restored");

        // -------------------------------------------------------------
        // 5. STORED XSS PROTECTED (SECTION 3 & 7)
        // -------------------------------------------------------------
        console.log("\n--- Testing 5. Stored XSS Protected ---");
        const cleanStoredSec = await request("GET", "/stored-secure");
        assert(cleanStoredSec.statusCode === 200, "Stored secure route returns 200");
        assert(cleanStoredSec.body.includes("PROTECTED"), "Green 'PROTECTED' indicator displayed");
        assert(cleanStoredSec.body.includes("● System Operational"), "Status is 'System Operational'");
        assert(cleanStoredSec.body.includes("College Portal Official Announcements"), "Original portal announcement intact");

        // Submit comment through protected pipeline
        const safeComment = "comment=" + encodeURIComponent("Testing student feedback submission.");
        const protSubmit = await request("POST", "/submit-comment", {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": Buffer.byteLength(safeComment)
        }, safeComment);
        assert(protSubmit.statusCode === 302, "Protected submission succeeded and redirected");
        assert(protSubmit.headers.location === "/stored-secure?success=1", "Redirected back to protected stored page");

        // -------------------------------------------------------------
        // 6. DOM-BASED XSS VULNERABLE & BANNER (SECTION 4 & 6)
        // -------------------------------------------------------------
        console.log("\n--- Testing 6. DOM-Based XSS Vulnerable ---");
        const domDemo = await request("GET", "/dom-demo");
        assert(domDemo.statusCode === 200, "DOM demo route returns 200");
        assert(domDemo.body.includes("Student Portal Dashboard - Official Portal"), "Original dashboard heading present before testing");
        assert(domDemo.body.includes("Legitimate System Status: All Systems Operational"), "Original system status card present");
        assert(domDemo.body.includes("● System Operational"), "Initial status badge is 'System Operational'");
        assert(domDemo.body.includes("DOM-BASED XSS — PAGE CONTENT MODIFIED"), "Exact heading 'DOM-BASED XSS — PAGE CONTENT MODIFIED' defined in banner container");
        assert(domDemo.body.includes("Reset Page"), "Reset Page button present");

        const domJs = fs.readFileSync(path.join(__dirname, "public", "dom-demo.js"), "utf8");
        assert(domJs.includes("output.innerHTML = message"), "Vulnerable DOM sink innerHTML retained");
        assert(domJs.includes("alertBanner.style.display = \"block\""), "Alert banner activated dynamically on defacement");
        assert(domJs.includes("CRITICAL COMPROMISE"), "Status changed dynamically to CRITICAL COMPROMISE in client memory");
        assert(domJs.includes("⚠️ DEFACED: Student Portal Tampered via DOM XSS"), "Dashboard heading modified dynamically");

        // -------------------------------------------------------------
        // 7. DOM-BASED XSS PROTECTED (SECTION 7)
        // -------------------------------------------------------------
        console.log("\n--- Testing 7. DOM-Based XSS Protected ---");
        const domSecure = await request("GET", "/dom-secure");
        assert(domSecure.statusCode === 200, "DOM secure route returns 200");
        assert(domSecure.body.includes("PROTECTED"), "Green 'PROTECTED' indicator displayed");
        assert(domSecure.body.includes("● System Operational"), "Status is 'System Operational'");
        assert(domSecure.body.includes("Student Portal Dashboard - Official Portal"), "Original dashboard heading intact");
        assert(domSecure.body.includes("Reset Page"), "Reset Page button present in protected DOM demo");

        const domSecureJs = fs.readFileSync(path.join(__dirname, "public", "dom-secure.js"), "utf8");
        assert(domSecureJs.includes("textContent"), "Protected script strictly uses safe textContent");
        assert(!domSecureJs.includes("innerHTML"), "Protected script avoids unsafe innerHTML");

        // -------------------------------------------------------------
        // 8. PREVENTION SYSTEM HUB (SECTION 7 & 9)
        // -------------------------------------------------------------
        console.log("\n--- Testing 8. Prevention System Hub ---");
        const prevHub = await request("GET", "/prevention");
        assert(prevHub.statusCode === 200, "Prevention hub route returns 200");
        assert(prevHub.body.includes("XSS Prevention System"), "Prevention hub heading present");
        assert(prevHub.body.includes("/reflected-secure"), "Link to Reflected Protected present");
        assert(prevHub.body.includes("/stored-secure"), "Link to Stored Protected present");
        assert(prevHub.body.includes("/dom-secure"), "Link to DOM Protected present");

        // -------------------------------------------------------------
        // 9. PHASE 2 INPUT VALIDATION API
        // -------------------------------------------------------------
        console.log("\n--- Testing 9. Server Input Validation API ---");
        const tc01 = await request("POST", "/api/test-input", { "Content-Type": "application/json" }, JSON.stringify({ input: "Hello, this is my comment." }));
        assert(JSON.parse(tc01.body).valid === true, "Normal text input accepted by server validation");

        const tc02 = await request("POST", "/api/test-input", { "Content-Type": "application/json" }, JSON.stringify({ input: "   " }));
        assert(JSON.parse(tc02.body).valid === false, "Empty whitespace rejected by server validation");

        const tc03 = await request("POST", "/api/test-input", { "Content-Type": "application/json" }, JSON.stringify({ input: "A".repeat(505) }));
        assert(JSON.parse(tc03.body).valid === false, "Overlength string rejected by server validation");

        // -------------------------------------------------------------
        // 10. TERMINAL OUTPUT & DUAL PHASE ROUTES
        // -------------------------------------------------------------
        console.log("\n--- Testing 10. Terminal Output & Dual Phase Routes ---");
        const serverFileContent = fs.readFileSync(path.join(__dirname, "server.js"), "utf8");
        assert(serverFileContent.includes("Phase 1 (Demonstration): http://localhost:${PORT}"), "Terminal log contains Phase 1 (Demonstration) link");
        assert(serverFileContent.includes("Phase 2 (Prevention):    http://localhost:${PORT}/prevention"), "Terminal log contains Phase 2 (Prevention) link");
        assert(!serverFileContent.includes("Reflected Vulnerable:  http://localhost:${PORT}"), "Removed individual Reflected terminal link");
        assert(!serverFileContent.includes("Stored Vulnerable:     http://localhost:${PORT}"), "Removed individual Stored terminal link");
        assert(!serverFileContent.includes("DOM Vulnerable:        http://localhost:${PORT}"), "Removed individual DOM terminal link");

        const demoRes = await request("GET", "/demonstration");
        assert(demoRes.statusCode === 200, "Route /demonstration returns 200");
        assert(demoRes.body.includes("Phase 1: XSS Vulnerability Demonstrations"), "/demonstration shows Phase 1 Demonstrations");

        const phase1Res = await request("GET", "/phase1");
        assert(phase1Res.statusCode === 200, "Route /phase1 returns 200");

        const phase2Res = await request("GET", "/phase2");
        assert(phase2Res.statusCode === 302 && phase2Res.headers.location === "/prevention", "Route /phase2 redirects to /prevention");

        console.log(`\n==========================================================`);
        console.log(`TOTAL TESTS: ${passed + failed} | PASSED: ${passed} | FAILED: ${failed}`);
        console.log(`==========================================================`);

        server.close();
        process.exit(failed > 0 ? 1 : 0);
    } catch (err) {
        console.error("Test execution error:", err);
        if (server) server.close();
        process.exit(1);
    }
}

runTests();
