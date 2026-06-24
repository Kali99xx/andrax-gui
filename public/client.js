// Initialize Socket.io connection
const socket = io();

// -------------------------------------------------------------
// 1. TOOL CONFIGURATIONS & DYNAMIC PARAMETER SCHEMAS
// -------------------------------------------------------------
const toolTemplates = {
    nmap: {
        command: "nmap",
        fields: [
            { label: "Target Host / IP", name: "target", type: "text", placeholder: "e.g. 192.168.1.1 or google.com", required: true },
            { label: "Ports to Scan", name: "ports", type: "text", placeholder: "e.g. -p- or -p 80,443 (blank for default)" },
            { label: "Scan Mode", name: "scan_type", type: "select", options: [
                { label: "Standard Quick Scan", value: "-F" },
                { label: "Service Version Detection & OS Check", value: "-sV -O" },
                { label: "Default Vulnerability Scripts & Services", value: "-sC -sV" },
                { label: "Ping Scan (Discover live hosts)", value: "-sn" },
                { label: "Stealth SYN Scan", value: "-sS" }
            ], default: "-F" },
            { label: "Timing Template", name: "timing", type: "select", options: [
                { label: "T4 (Aggressive/Fast)", value: "-T4" },
                { label: "T3 (Normal)", value: "-T3" },
                { label: "T5 (Insane/Very Fast)", value: "-T5" },
                { label: "T2 (Polite/Slow)", value: "-T2" }
            ], default: "-T4" },
            { label: "Skip Host Discovery (-Pn)", name: "skip_ping", type: "checkbox", default: true }
        ],
        builder: (values) => {
            const ports = values.ports ? values.ports.trim() : '';
            const skipPing = values.skip_ping ? '-Pn' : '';
            return `nmap ${values.scan_type} ${values.timing} ${skipPing} ${ports} ${values.target}`;
        },
        preloads: [
            {
                label: "Service & OS Detection",
                desc: "Identify versions, OS details, and default scripts (-sV -O -sC)",
                values: { target: "192.168.1.1", scan_type: "-sV -O", timing: "-T4", skip_ping: true, ports: "" }
            },
            {
                label: "Quick Scan",
                desc: "Fast ports scan using top 100 common ports (-F)",
                values: { target: "192.168.1.1", scan_type: "-F", timing: "-T4", skip_ping: true, ports: "" }
            },
            {
                label: "Vulnerability Scan",
                desc: "Run NSE vulnerability scripts to find security flaws",
                values: { target: "192.168.1.1", scan_type: "-sC -sV", timing: "-T4", skip_ping: true, ports: "" }
            },
            {
                label: "Full TCP Scan (All Ports)",
                desc: "Scan all 65535 TCP ports aggressively",
                values: { target: "192.168.1.1", scan_type: "-sS", timing: "-T4", skip_ping: true, ports: "-p-" }
            },
            {
                label: "Host Discovery (Ping Sweep)",
                desc: "Detect active online hosts in a subnet without port scanning",
                values: { target: "192.168.1.0/24", scan_type: "-sn", timing: "-T3", skip_ping: false, ports: "" }
            }
        ]
    },
    wifite: {
        command: "sudo wifite",
        fields: [
            { label: "Interface Name", name: "interface", type: "text", placeholder: "e.g. wlan0", default: "wlan0", required: true },
            { label: "Kill Conflicting Processes (--kill)", name: "kill", type: "checkbox", default: true },
            { label: "Scan Frequency Bands", name: "band", type: "select", options: [
                { label: "2.4 GHz Only", value: "" },
                { label: "5 GHz Only", value: "-5" },
                { label: "Both 2.4 GHz and 5 GHz", value: "-5 --band abg" }
            ], default: "" },
            { label: "Target BSSID (Optional)", name: "bssid", type: "text", placeholder: "e.g. AA:BB:CC:DD:EE:FF" },
            { label: "Extra Arguments", name: "extra", type: "text", placeholder: "e.g. --pmkid or --wps" }
        ],
        builder: (values) => {
            const kill = values.kill ? '--kill' : '';
            const bssid = values.bssid ? `--bssid ${values.bssid.trim()}` : '';
            const extra = values.extra ? values.extra.trim() : '';
            return `sudo wifite -i ${values.interface} ${kill} ${values.band} ${bssid} ${extra}`;
        },
        preloads: [
            {
                label: "Automated Attack (All)",
                desc: "Fully automatic scan, deauth, and attack on all targets",
                values: { interface: "wlan0mon", kill: true, band: "", bssid: "", extra: "" }
            },
            {
                label: "5 GHz Spectrum Attack",
                desc: "Focus wireless attack operations on 5GHz band only",
                values: { interface: "wlan0mon", kill: true, band: "-5", bssid: "", extra: "" }
            },
            {
                label: "PMKID Capture Focus",
                desc: "Target PMKID associations to crack WPA2 without clients",
                values: { interface: "wlan0mon", kill: true, band: "", bssid: "", extra: "--pmkid" }
            },
            {
                label: "WPS Attack Only",
                desc: "Target WPS-enabled networks via Pixie-Dust and PIN brute-force",
                values: { interface: "wlan0mon", kill: true, band: "", bssid: "", extra: "--wps" }
            },
            {
                label: "Target Specific BSSID",
                desc: "Isolate attack operations to a single target AP MAC address",
                values: { interface: "wlan0mon", kill: true, band: "", bssid: "11:22:33:44:55:66", extra: "" }
            }
        ]
    },
    sqlmap: {
        command: "sqlmap",
        fields: [
            { label: "Target URL", name: "url", type: "text", placeholder: "http://example.com/vuln.php?id=1", required: true },
            { label: "Database Enumeration", name: "dbs", type: "checkbox", default: true },
            { label: "Risk level", name: "risk", type: "select", options: [
                { label: "1 (Low / Safe)", value: "1" },
                { label: "2 (Medium)", value: "2" },
                { label: "3 (High / Aggressive)", value: "3" }
            ], default: "1" },
            { label: "Test level", name: "level", type: "select", options: [
                { label: "1 (Default)", value: "1" },
                { label: "3 (Includes headers)", value: "3" },
                { label: "5 (Includes headers + host payloads)", value: "5" }
            ], default: "1" },
            { label: "Batch Mode (Automatic yes to prompts)", name: "batch", type: "checkbox", default: true },
            { label: "Extra Arguments", name: "extra", type: "text", placeholder: "e.g. --dbms=mysql or --crawl=2" }
        ],
        builder: (values) => {
            const dbs = values.dbs ? '--dbs' : '';
            const batch = values.batch ? '--batch' : '';
            const extra = values.extra ? values.extra.trim() : '';
            return `sqlmap -u "${values.url}" --risk=${values.risk} --level=${values.level} ${dbs} ${batch} ${extra}`;
        },
        preloads: [
            {
                label: "Enumerate Databases",
                desc: "Find SQL injections and discover all database names",
                values: { url: "http://example.com/vuln.php?id=1", dbs: true, risk: "1", level: "1", batch: true, extra: "" }
            },
            {
                label: "Quick Vuln Check",
                desc: "Perform a quick injection test without dumping schemas",
                values: { url: "http://example.com/vuln.php?id=1", dbs: false, risk: "1", level: "1", batch: true, extra: "" }
            },
            {
                label: "Enumerate Current DB & User",
                desc: "Identify active database database name and connection user",
                values: { url: "http://example.com/vuln.php?id=1", dbs: false, risk: "1", level: "1", batch: true, extra: "--current-user --current-db" }
            },
            {
                label: "Aggressive Risk Injection",
                desc: "Deep scan with maximum risk/level settings for hidden flaws",
                values: { url: "http://example.com/vuln.php?id=1", dbs: true, risk: "3", level: "5", batch: true, extra: "" }
            },
            {
                label: "Interactive OS Shell",
                desc: "Try to spawn an interactive shell on the server back-end",
                values: { url: "http://example.com/vuln.php?id=1", dbs: false, risk: "1", level: "1", batch: true, extra: "--os-shell" }
            }
        ]
    },
    bettercap: {
        command: "sudo bettercap",
        fields: [
            { label: "Interface Name", name: "interface", type: "text", placeholder: "e.g. wlan0", default: "wlan0", required: true },
            { label: "Caplet script path (Optional)", name: "caplet", type: "text", placeholder: "e.g. http-req-dump.cap" },
            { label: "Extra Arguments", name: "extra", type: "text", placeholder: "e.g. -eval \"net.probe on\"" }
        ],
        builder: (values) => {
            const caplet = values.caplet ? `-caplet ${values.caplet.trim()}` : '';
            const extra = values.extra ? values.extra.trim() : '';
            return `sudo bettercap -iface ${values.interface} ${caplet} ${extra}`;
        },
        preloads: [
            {
                label: "Active Host Discovery",
                desc: "Probe network and show live subnet nodes",
                values: { interface: "wlan0", caplet: "", extra: "-eval \"net.probe on; net.show\"" }
            },
            {
                label: "Real-time Sniffer",
                desc: "Capture and print raw local network traffic packets",
                values: { interface: "wlan0", caplet: "", extra: "-eval \"net.sniff on\"" }
            },
            {
                label: "ARP Spoof Target Node",
                desc: "Poison ARP cache to redirect target to this controller",
                values: { interface: "wlan0", caplet: "", extra: "-eval \"set arp.spoof.targets 192.168.1.105; arp.spoof on\"" }
            },
            {
                label: "Load Http Request Dumper",
                desc: "Launch with script to dump HTTP server connections",
                values: { interface: "wlan0", caplet: "http-req-dump.cap", extra: "" }
            }
        ]
    },
    "thc-hydra": {
        command: "hydra",
        fields: [
            { label: "Target IP / Domain", name: "target", type: "text", placeholder: "192.168.1.100", required: true },
            { label: "Service Type", name: "service", type: "select", options: [
                { label: "SSH", value: "ssh" },
                { label: "FTP", value: "ftp" },
                { label: "Telnet", value: "telnet" },
                { label: "HTTP GET Request", value: "http-get" },
                { label: "MySQL", value: "mysql" }
            ], default: "ssh" },
            { label: "Login Username", name: "username", type: "text", placeholder: "e.g. admin (blank for wordlist)" },
            { label: "User List File (Optional)", name: "userlist", type: "text", placeholder: "e.g. /opt/wordlist/users.txt" },
            { label: "Password (Single)", name: "password", type: "text", placeholder: "e.g. password123 (blank for wordlist)" },
            { label: "Password Wordlist", name: "wordlist", type: "text", placeholder: "e.g. /usr/share/wordlists/rockyou.txt" },
            { label: "Threads count", name: "threads", type: "text", placeholder: "4", default: "4" }
        ],
        builder: (values) => {
            const userPart = values.username ? `-l ${values.username.trim()}` : (values.userlist ? `-L ${values.userlist.trim()}` : '-l admin');
            const passPart = values.password ? `-p ${values.password.trim()}` : (values.wordlist ? `-P ${values.wordlist.trim()}` : '-P /usr/share/wordlists/rockyou.txt');
            const threads = values.threads ? `-t ${values.threads}` : '-t 4';
            return `hydra ${userPart} ${passPart} ${threads} ${values.target} ${values.service}`;
        },
        preloads: [
            {
                label: "SSH Root Brute Force",
                desc: "Attack SSH on root account using rockyou wordlist",
                values: { target: "192.168.1.100", service: "ssh", username: "root", userlist: "", password: "", wordlist: "/usr/share/wordlists/rockyou.txt", threads: "4" }
            },
            {
                label: "FTP Admin Brute Force",
                desc: "Attack FTP service for username admin with standard passlist",
                values: { target: "192.168.1.100", service: "ftp", username: "admin", userlist: "", password: "", wordlist: "/usr/share/wordlists/rockyou.txt", threads: "4" }
            },
            {
                label: "Telnet Userlist Scan",
                desc: "Brute force telnet login using custom list files for user & pass",
                values: { target: "192.168.1.100", service: "telnet", username: "", userlist: "users.txt", password: "", wordlist: "passwords.txt", threads: "8" }
            }
        ]
    },
    hashcat: {
        command: "hashcat",
        fields: [
            { label: "Hash Type / Mode", name: "mode", type: "select", options: [
                { label: "MD5 (Mode 0)", value: "0" },
                { label: "SHA-1 (Mode 100)", value: "100" },
                { label: "SHA-256 (Mode 1400)", value: "1400" },
                { label: "WPA/WPA2 PMK (Mode 2500 / 22000)", value: "22000" },
                { label: "NTLM (Mode 1000)", value: "1000" }
            ], default: "0" },
            { label: "Hash File Path", name: "hashfile", type: "text", placeholder: "/home/andrax/handshakes/hash.hc22000", required: true },
            { label: "Wordlist Path", name: "wordlist", type: "text", placeholder: "/usr/share/wordlists/rockyou.txt", required: true }
        ],
        builder: (values) => {
            return `hashcat -m ${values.mode} "${values.hashfile}" "${values.wordlist}"`;
        },
        preloads: [
            {
                label: "WPA/WPA2 Handshake Crack",
                desc: "Crack WPA/WPA2 PMKID handshakes (Mode 22000)",
                values: { mode: "22000", hashfile: "/home/andrax/handshakes/hash.hc22000", wordlist: "/usr/share/wordlists/rockyou.txt" }
            },
            {
                label: "MD5 Hash Recovery",
                desc: "Decipher standard MD5 hash strings with wordlist dictionary",
                values: { mode: "0", hashfile: "/home/andrax/hashes.txt", wordlist: "/usr/share/wordlists/rockyou.txt" }
            },
            {
                label: "SHA-256 Hash Recovery",
                desc: "Decipher SHA-256 hashes using Rockyou list",
                values: { mode: "1400", hashfile: "/home/andrax/sha256.txt", wordlist: "/usr/share/wordlists/rockyou.txt" }
            },
            {
                label: "NTLM Windows Hash Crack",
                desc: "Crack Windows NTLM user password hashes (Mode 1000)",
                values: { mode: "1000", hashfile: "/home/andrax/ntlm.txt", wordlist: "/usr/share/wordlists/rockyou.txt" }
            }
        ]
    },
    responder: {
        command: "sudo responder",
        fields: [
            { label: "Interface Name", name: "interface", type: "text", placeholder: "e.g. wlan0", default: "wlan0", required: true },
            { label: "Analyze Mode (Passive/Read-only)", name: "analyze", type: "checkbox", default: false },
            { label: "WPAC Proxy Mode (-w)", name: "wpad", type: "checkbox", default: true },
            { label: "NetBIOS Name Service Poisoning (-b)", name: "netbios", type: "checkbox", default: true },
            { label: "Extra Arguments", name: "extra", type: "text", placeholder: "e.g. -v" }
        ],
        builder: (values) => {
            const analyze = values.analyze ? '-A' : '';
            const wpad = values.wpad ? '-w' : '';
            const netbios = values.netbios ? '-b' : '';
            const extra = values.extra ? values.extra.trim() : '';
            return `sudo responder -I ${values.interface} ${analyze} ${wpad} ${netbios} ${extra}`;
        },
        preloads: [
            {
                label: "Active LLMNR/NBTNS Poisoning",
                desc: "Respond actively to LLMNR/NetBIOS requests with WPAD proxy",
                values: { interface: "wlan0", analyze: false, wpad: true, netbios: true, extra: "-d -v" }
            },
            {
                label: "Passive Traffic Analyze",
                desc: "Observe domain network requests silently without injecting packets",
                values: { interface: "wlan0", analyze: true, wpad: false, netbios: false, extra: "" }
            },
            {
                label: "Host Fingerprinting Scan",
                desc: "Passively map local subnet hosts OS details",
                values: { interface: "wlan0", analyze: false, wpad: false, netbios: false, extra: "-f" }
            }
        ]
    },
    nikto: {
        command: "nikto",
        fields: [
            { label: "Target Host URL / IP", name: "host", type: "text", placeholder: "http://example.com or 192.168.1.1", required: true },
            { label: "Target Port", name: "port", type: "text", placeholder: "80 (default)" },
            { label: "Tuning (Scan modules selection)", name: "tuning", type: "select", options: [
                { label: "All Tests (Default)", value: "x" },
                { label: "File Upload Tests Only", value: "0" },
                { label: "XSS & HTML Injection Tests Only", value: "4" },
                { label: "SQL Injection Tests Only", value: "9" }
            ], default: "x" }
        ],
        builder: (values) => {
            const port = values.port ? `-p ${values.port}` : '';
            return `nikto -h "${values.host}" -Tuning ${values.tuning} ${port}`;
        },
        preloads: [
            {
                label: "Standard HTTP Scan",
                desc: "Search web server configurations and common files for flaws",
                values: { host: "http://192.168.1.1", port: "", tuning: "x" }
            },
            {
                label: "Scan Port 443 with HTTPS",
                desc: "Scan SSL web portals with secure mode enabled",
                values: { host: "https://192.168.1.1", port: "443", tuning: "x" }
            },
            {
                label: "SQL Injection Focus",
                desc: "Tune scanner options to specifically audit SQL injection points",
                values: { host: "http://192.168.1.1", port: "", tuning: "9" }
            },
            {
                label: "Cross-Site Scripting (XSS) Focus",
                desc: "Restrict checks to cross-site scripting and HTML payloads",
                values: { host: "http://192.168.1.1", port: "", tuning: "4" }
            }
        ]
    },
    commix: {
        command: "commix",
        fields: [
            { label: "Target URL", name: "url", type: "text", placeholder: "http://example.com/vuln.php?addr=127.0.0.1", required: true },
            { label: "Batch Mode (Assume default answers)", name: "batch", type: "checkbox", default: true },
            { label: "Extra Arguments", name: "extra", type: "text", placeholder: "e.g. --cookie=\"PHPSESSID=...\"" }
        ],
        builder: (values) => {
            const batch = values.batch ? '--batch' : '';
            const extra = values.extra ? values.extra.trim() : '';
            return `commix --url="${values.url}" ${batch} ${extra}`;
        },
        preloads: [
            {
                label: "Quick Command Injection Check",
                desc: "Test input parameter for command injection vulnerabilities",
                values: { url: "http://example.com/vuln.php?addr=127.0.0.1", batch: true, extra: "" }
            },
            {
                label: "Aggressive Header injection",
                desc: "Scan HTTP custom headers and calculate entropy",
                values: { url: "http://example.com/vuln.php", batch: true, extra: "--header=\"Cookie: PHPSESSID=test\" --entropy" }
            },
            {
                label: "Automated System Command",
                desc: "Try to run system ID queries automatically in non-interactive batch",
                values: { url: "http://example.com/vuln.php?addr=127.0.0.1", batch: true, extra: "--os-cmd=\"id\"" }
            }
        ]
    },
    slowhttptest: {
        command: "slowhttptest",
        fields: [
            { label: "Target URL", name: "url", type: "text", placeholder: "http://example.com", required: true },
            { label: "Connections count (-c)", name: "connections", type: "text", placeholder: "1000", default: "1000" },
            { label: "Slow HTTP Attack Mode", name: "mode", type: "select", options: [
                { label: "Slowloris (HTTP GET headers)", value: "-H" },
                { label: "Slow POST (HTTP Body POST)", value: "-B" },
                { label: "Range Attack (Range headers)", value: "-R" }
            ], default: "-H" },
            { label: "Connection rate per second (-r)", name: "rate", type: "text", placeholder: "200", default: "200" },
            { label: "Timeout Interval (-t)", name: "timeout", type: "text", placeholder: "10", default: "10" }
        ],
        builder: (values) => {
            return `slowhttptest -u "${values.url}" -c ${values.connections} ${values.mode} -r ${values.rate} -t ${values.timeout}`;
        },
        preloads: [
            {
                label: "Slowloris DOS Attack",
                desc: "Hold HTTP connections open by sending partial HTTP headers (-H)",
                values: { url: "http://example.com", connections: "1000", mode: "-H", rate: "200", timeout: "10" }
            },
            {
                label: "Slow POST Attack",
                desc: "Hold HTTP connections open by sending partial POST bodies (-B)",
                values: { url: "http://example.com", connections: "1000", mode: "-B", rate: "200", timeout: "10" }
            },
            {
                label: "Slow Read Attack",
                desc: "Read response data extremely slowly to consume resources (-R)",
                values: { url: "http://example.com", connections: "1000", mode: "-R", rate: "200", timeout: "10" }
            }
        ]
    }
};

// -------------------------------------------------------------
// 2. STATE MANAGER VARIABLES
// -------------------------------------------------------------
let allTools = [];
let selectedTool = null;
let commandRunning = false;
let startMenuOpen = false;

// SSH Client variables
let sshConnected = false;

// Media Screencast variables
let screencastStream = null;
let mediaRecorder = null;
let recordedChunks = [];

// AI Assistant Conversational thread memory
let aiThread = [
    { role: 'assistant', content: 'Hello. I am integrated with your environment and can analyze scan results, suggest commands, or help secure the node. Select a provider on the left and input credentials to activate.' }
];

// Window z-indexing sequence
let topZIndex = 50;

// Window locations defaults
const defaultLayouts = {
    "window-tools": { top: "30px", left: "40px", width: "500px", height: "500px" },
    "window-terminal": { top: "60px", left: "580px", width: "620px", height: "470px" },
    "window-afos": { top: "150px", left: "150px", width: "680px", height: "480px" },
    "window-sysinfo": { top: "200px", left: "100px", width: "480px", height: "350px" },
    "window-ssh": { top: "100px", left: "300px", width: "640px", height: "480px" },
    "window-tailscale": { top: "80px", left: "120px", width: "620px", height: "460px" },
    "window-screencast": { top: "140px", left: "240px", width: "600px", height: "490px" },
    "window-ai": { top: "90px", left: "220px", width: "680px", height: "500px" },
    "window-customizer": { top: "180px", left: "450px", width: "460px", height: "380px" }
};

// -------------------------------------------------------------
// 3. WINDOW MANAGER (DRAG / RESIZE / FOCUS / TASKBAR)
// -------------------------------------------------------------
const desktopArea = document.getElementById('desktop-area');

// Dragging functionality
function initDraggability(windowElement) {
    const header = windowElement.querySelector('.window-header');
    if (!header) return;

    header.addEventListener('mousedown', (e) => {
        if (e.target.closest('.window-controls') || windowElement.classList.contains('maximized')) return;
        
        focusWindow(windowElement);
        
        const rect = windowElement.getBoundingClientRect();
        // Incorporate current scroll offset in Client offset
        const offsetX = e.clientX - rect.left;
        const offsetY = e.clientY - rect.top;

        function onMouseMove(moveEvent) {
            // Find absolute coordinates relative to desktop-area container parent
            const parentRect = desktopArea.getBoundingClientRect();
            const x = moveEvent.clientX - parentRect.left - offsetX;
            const y = moveEvent.clientY - parentRect.top - offsetY;
            
            windowElement.style.left = `${x}px`;
            windowElement.style.top = `${y}px`;
            adjustDesktopSize();
        }

        function onMouseUp() {
            document.removeEventListener('mousemove', onMouseMove);
            document.removeEventListener('mouseup', onMouseUp);
        }

        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
    });

    // Touch support for dragging (Mobile friendly)
    header.addEventListener('touchstart', (e) => {
        if (e.target.closest('.window-controls') || windowElement.classList.contains('maximized')) return;
        
        focusWindow(windowElement);
        
        const touch = e.touches[0];
        const rect = windowElement.getBoundingClientRect();
        const offsetX = touch.clientX - rect.left;
        const offsetY = touch.clientY - rect.top;

        function onTouchMove(moveEvent) {
            const t = moveEvent.touches[0];
            const parentRect = desktopArea.getBoundingClientRect();
            const x = t.clientX - parentRect.left - offsetX;
            const y = t.clientY - parentRect.top - offsetY;
            
            windowElement.style.left = `${x}px`;
            windowElement.style.top = `${y}px`;
            adjustDesktopSize();
        }

        function onTouchEnd() {
            document.removeEventListener('touchmove', onTouchMove);
            document.removeEventListener('touchend', onTouchEnd);
        }

        document.addEventListener('touchmove', onTouchMove);
        document.addEventListener('touchend', onTouchEnd);
    });
}

// Resizing functionality
function initResizability(windowElement) {
    const resizeHandles = ['r', 'b', 'se'];
    
    resizeHandles.forEach(h => {
        const resizer = document.createElement('div');
        resizer.className = `win-resizer ${h}`;
        windowElement.appendChild(resizer);

        resizer.addEventListener('mousedown', (e) => {
            e.preventDefault();
            focusWindow(windowElement);
            
            const startWidth = windowElement.offsetWidth;
            const startHeight = windowElement.offsetHeight;
            const startX = e.clientX;
            const startY = e.clientY;

            function onMouseMove(moveEvent) {
                const deltaX = moveEvent.clientX - startX;
                const deltaY = moveEvent.clientY - startY;

                if (h === 'r' || h === 'se') {
                    windowElement.style.width = `${Math.max(250, startWidth + deltaX)}px`;
                }
                if (h === 'b' || h === 'se') {
                    windowElement.style.height = `${Math.max(150, startHeight + deltaY)}px`;
                }
                adjustDesktopSize();
            }

            // Clean event listeners on mouse release
            function onMouseUp() {
                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);
            }

            document.addEventListener('mousemove', onMouseMove);
            document.addEventListener('mouseup', onMouseUp);
        });
    });
}

// Dynamically expand desktop scroll area to fit overflowing floating windows
function adjustDesktopSize() {
    let maxBottom = window.innerHeight - 48; // minimum is viewport minus taskbar
    let maxRight = window.innerWidth;
    
    const windows = document.querySelectorAll('.desktop-window');
    windows.forEach(win => {
        if (!win.classList.contains('hidden') && !win.classList.contains('minimized')) {
            const topVal = parseFloat(win.style.top) || 0;
            const leftVal = parseFloat(win.style.left) || 0;
            const heightVal = win.offsetHeight || 0;
            const widthVal = win.offsetWidth || 0;
            
            const bottom = topVal + heightVal;
            const right = leftVal + widthVal;
            
            if (bottom > maxBottom) maxBottom = bottom;
            if (right > maxRight) maxRight = right;
        }
    });
    
    // Add breathing room
    desktopArea.style.minHeight = `${maxBottom + 60}px`;
    desktopArea.style.minWidth = `${maxRight + 20}px`;
}

// Focus window helper
function focusWindow(windowElement) {
    if (windowElement.classList.contains('active-win')) return;
    
    document.querySelectorAll('.desktop-window').forEach(w => w.classList.remove('active-win'));
    windowElement.classList.add('active-win');
    topZIndex += 1;
    windowElement.style.zIndex = topZIndex;

    updateTaskbarHighlights();
}

// Show/Toggle window from shortcut or menu click
function openWindow(id) {
    const win = document.getElementById(id);
    if (!win) return;
    
    win.classList.remove('hidden');
    win.classList.remove('minimized');
    focusWindow(win);
    
    syncTaskbarItems();
    adjustDesktopSize();
}

// Window control button events setup
function setupWindowControlListeners(windowElement) {
    const minBtn = windowElement.querySelector('.win-btn.min');
    const maxBtn = windowElement.querySelector('.win-btn.max');
    const closeBtn = windowElement.querySelector('.win-btn.close');

    if (minBtn) {
        minBtn.addEventListener('click', () => {
            windowElement.classList.add('minimized');
            syncTaskbarItems();
            adjustDesktopSize();
        });
    }

    if (maxBtn) {
        maxBtn.addEventListener('click', () => {
            if (windowElement.classList.contains('maximized')) {
                windowElement.classList.remove('maximized');
                windowElement.style.top = windowElement.dataset.prevTop || '100px';
                windowElement.style.left = windowElement.dataset.prevLeft || '100px';
                windowElement.style.width = windowElement.dataset.prevWidth || '500px';
                windowElement.style.height = windowElement.dataset.prevHeight || '400px';
                maxBtn.innerHTML = '<i class="fa-solid fa-expand"></i>';
            } else {
                windowElement.dataset.prevTop = windowElement.style.top;
                windowElement.dataset.prevLeft = windowElement.style.left;
                windowElement.dataset.prevWidth = windowElement.style.width;
                windowElement.dataset.prevHeight = windowElement.style.height;

                windowElement.classList.add('maximized');
                windowElement.style.top = '0';
                windowElement.style.left = '0';
                windowElement.style.width = '100%';
                windowElement.style.height = 'calc(100vh - 48px)';
                maxBtn.innerHTML = '<i class="fa-solid fa-compress"></i>';
            }
            adjustDesktopSize();
        });
    }

    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            windowElement.classList.add('hidden');
            syncTaskbarItems();
            adjustDesktopSize();
        });
    }

    windowElement.addEventListener('mousedown', () => {
        focusWindow(windowElement);
    });
}

// TASKBAR items syncing
const taskbarItems = document.getElementById('taskbar-items');
function syncTaskbarItems() {
    taskbarItems.innerHTML = '';
    
    document.querySelectorAll('.desktop-window').forEach(w => {
        if (!w.classList.contains('hidden')) {
            const winId = w.id;
            const winTitle = w.querySelector('.window-title').innerText;
            const winIcon = w.querySelector('.window-title i').className;
            
            const btn = document.createElement('div');
            btn.className = 'task-item';
            if (w.classList.contains('active-win') && !w.classList.contains('minimized')) {
                btn.classList.add('active');
            }
            btn.innerHTML = `<i class="${winIcon}"></i><span>${winTitle}</span>`;
            
            btn.addEventListener('click', () => {
                if (w.classList.contains('minimized')) {
                    w.classList.remove('minimized');
                    focusWindow(w);
                } else if (w.classList.contains('active-win')) {
                    w.classList.add('minimized');
                    w.classList.remove('active-win');
                } else {
                    focusWindow(w);
                }
                syncTaskbarItems();
            });
            taskbarItems.appendChild(btn);
        }
    });
}

function updateTaskbarHighlights() {
    document.querySelectorAll('.task-item').forEach(item => {
        const itemText = item.querySelector('span').innerText;
        item.classList.remove('active');
        
        document.querySelectorAll('.desktop-window').forEach(w => {
            if (w.classList.contains('active-win') && !w.classList.contains('minimized')) {
                if (w.querySelector('.window-title').innerText === itemText) {
                    item.classList.add('active');
                }
            }
        });
    });
}

// Reset desktop windows positioning
function resetWindowPositions() {
    document.querySelectorAll('.desktop-window').forEach(w => {
        const layout = defaultLayouts[w.id];
        if (layout) {
            w.classList.remove('maximized');
            w.classList.remove('minimized');
            w.style.top = layout.top;
            w.style.left = layout.left;
            w.style.width = layout.width;
            w.style.height = layout.height;
        }
    });
}

// Cascade Windows layout helper
function cascadeWindows() {
    let offset = 40;
    let index = 0;
    
    document.querySelectorAll('.desktop-window').forEach(w => {
        if (!w.classList.contains('hidden') && !w.classList.contains('minimized')) {
            w.classList.remove('maximized');
            w.style.left = `${offset + (index * 30)}px`;
            w.style.top = `${offset + (index * 30)}px`;
            focusWindow(w);
            index++;
        }
    });
}

// -------------------------------------------------------------
// 4. MATRIX BACKGROUND ANIMATION EFFECT
// -------------------------------------------------------------
const matrixCanvas = document.getElementById('matrix-canvas');
const ctx = matrixCanvas.getContext('2d');
let matrixInterval = null;

function resizeMatrixCanvas() {
    matrixCanvas.width = window.innerWidth;
    matrixCanvas.height = window.innerHeight;
}

function runMatrixRain() {
    if (matrixInterval) clearInterval(matrixInterval);
    resizeMatrixCanvas();
    
    const katakana = 'ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ1234567890';
    const alphabet = katakana.split('');
    const fontSize = 14;
    const columns = matrixCanvas.width / fontSize;
    
    const rainDrops = [];
    for (let x = 0; x < columns; x++) {
        rainDrops[x] = 1;
    }
    
    const draw = () => {
        ctx.fillStyle = 'rgba(2, 5, 14, 0.08)';
        ctx.fillRect(0, 0, matrixCanvas.width, matrixCanvas.height);
        
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--primary').trim() || '#10b981';
        ctx.font = fontSize + 'px monospace';
        
        for (let i = 0; i < rainDrops.length; i++) {
            const text = alphabet[Math.floor(Math.random() * alphabet.length)];
            const x = i * fontSize;
            const y = rainDrops[i] * fontSize;
            
            ctx.fillText(text, x, y);
            
            if (y > matrixCanvas.height && Math.random() > 0.975) {
                rainDrops[i] = 0;
            }
            rainDrops[i]++;
        }
    };
    
    matrixInterval = setInterval(draw, 33);
}

// -------------------------------------------------------------
// 5. THEME & VISUAL CUSTOMIZATION CONTROLS
// -------------------------------------------------------------
const themeColorButtons = document.querySelectorAll('.theme-color-btn');
const themeWpButtons = document.querySelectorAll('.theme-wp-btn');
const opacitySlider = document.getElementById('window-opacity-slider');
const opacityVal = document.getElementById('opacity-val');

themeColorButtons.forEach(btn => {
    btn.addEventListener('click', () => {
        themeColorButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        const theme = btn.getAttribute('data-theme');
        let primaryColor, glowColor;
        
        if (theme === 'green') {
            primaryColor = '#10b981';
            glowColor = 'rgba(16, 185, 129, 0.45)';
        } else if (theme === 'purple') {
            primaryColor = '#a855f7';
            glowColor = 'rgba(168, 85, 247, 0.45)';
        } else if (theme === 'amber') {
            primaryColor = '#f59e0b';
            glowColor = 'rgba(245, 158, 11, 0.45)';
        } else if (theme === 'red') {
            primaryColor = '#ef4444';
            glowColor = 'rgba(239, 68, 68, 0.45)';
        }
        
        document.documentElement.style.setProperty('--primary', primaryColor);
        document.documentElement.style.setProperty('--primary-glow', glowColor);
        document.documentElement.style.setProperty('--border-focus', primaryColor);
        
        runMatrixRain();
    });
});

const desktopWallpaper = document.getElementById('desktop-wallpaper');
themeWpButtons.forEach(btn => {
    btn.addEventListener('click', () => {
        themeWpButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        const wp = btn.getAttribute('data-wp');
        
        if (wp === 'matrix') {
            matrixCanvas.style.opacity = '0.75';
            desktopWallpaper.classList.remove('active');
            desktopWallpaper.style.backgroundImage = 'none';
        } else if (wp === 'wallpaper') {
            matrixCanvas.style.opacity = '0';
            desktopWallpaper.style.backgroundImage = "url('wallpaper.jpg')";
            desktopWallpaper.classList.add('active');
        } else if (wp === 'dark') {
            matrixCanvas.style.opacity = '0';
            desktopWallpaper.classList.remove('active');
            desktopWallpaper.style.backgroundImage = 'none';
        } else if (wp === 'grid') {
            matrixCanvas.style.opacity = '0.12';
            desktopWallpaper.classList.remove('active');
            desktopWallpaper.style.backgroundImage = 'none';
        }
    });
});

opacitySlider.addEventListener('input', () => {
    const val = opacitySlider.value;
    opacityVal.textContent = `${val}%`;
    document.documentElement.style.setProperty('--window-opacity', (val / 100));
});

document.getElementById('btn-cascade-windows').addEventListener('click', cascadeWindows);
document.getElementById('btn-reset-layout').addEventListener('click', resetWindowPositions);

// -------------------------------------------------------------
// 6. ANDRAX START MENU OVERLAY & TRAY CLOCK
// -------------------------------------------------------------
const startBtn = document.getElementById('start-btn');
const startMenu = document.getElementById('start-menu');

startBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    startMenuOpen = !startMenuOpen;
    if (startMenuOpen) {
        startMenu.classList.remove('hidden');
        startBtn.classList.add('active');
    } else {
        startMenu.classList.add('hidden');
        startBtn.classList.remove('active');
    }
});

document.addEventListener('click', () => {
    if (startMenuOpen) {
        startMenu.classList.add('hidden');
        startBtn.classList.remove('active');
        startMenuOpen = false;
    }
});

startMenu.addEventListener('click', (e) => {
    e.stopPropagation();
});

document.getElementById('menu-btn-shutdown').addEventListener('click', () => {
    if (confirm("Confirm Reboot of ANDRAX core container environment?")) {
        alert("Sending reboot signal to backend server system...");
    }
});

function runTrayClock() {
    const clockEl = document.getElementById('tray-clock');
    const update = () => {
        const d = new Date();
        clockEl.textContent = d.toLocaleTimeString();
    };
    update();
    setInterval(update, 1000);
}

// -------------------------------------------------------------
// 7. AUDIT TOOLS CONTROLLER
// -------------------------------------------------------------
const toolSearch = document.getElementById('tool-search');
const categoryFilter = document.getElementById('category-filter');
const toolSelect = document.getElementById('tool-select');
const toolInfoCard = document.getElementById('tool-info-card');
const infoName = document.getElementById('info-name');
const infoVersion = document.getElementById('info-version');
const infoCategory = document.getElementById('info-category');
const infoDesc = document.getElementById('info-desc');

const builderPlaceholder = document.getElementById('builder-placeholder');
const commandForm = document.getElementById('command-form');
const dynamicFields = document.getElementById('dynamic-fields');
const generatedCommand = document.getElementById('generated-command');
const copyCmdBtn = document.getElementById('copy-cmd-btn');
const runBtn = document.getElementById('run-btn');
const stopBtn = document.getElementById('stop-btn');

const terminalOutput = document.getElementById('terminal-output');
const terminalBadge = document.getElementById('terminal-badge');
const copyTerminalBtn = document.getElementById('copy-terminal-btn');
const clearTerminalBtn = document.getElementById('clear-terminal-btn');
const terminalStdin = document.getElementById('terminal-stdin');
const sendStdinBtn = document.getElementById('send-stdin-btn');

async function loadTools() {
    try {
        const response = await fetch('/api/tools');
        allTools = await response.json();
        populateCategories();
        renderToolDropdown();
        renderPackagesTable();
    } catch (e) {
        console.error("Failed to load tools database:", e);
    }
}

function populateCategories() {
    const categories = new Set();
    allTools.forEach(t => {
        if (t.category) {
            t.category.split(',').forEach(c => categories.add(c.trim()));
        }
    });
    
    categoryFilter.innerHTML = '<option value="all">All Categories</option>';
    Array.from(categories).sort().forEach(c => {
        const opt = document.createElement('option');
        opt.value = c;
        opt.textContent = c;
        categoryFilter.appendChild(opt);
    });
}

function renderToolDropdown() {
    const query = toolSearch.value.toLowerCase().trim();
    const cat = categoryFilter.value;
    
    toolSelect.innerHTML = '<option value="">-- Choose a Tool --</option>';
    
    const filtered = allTools.filter(t => {
        const matchesQuery = t.name.toLowerCase().includes(query) || t.description.toLowerCase().includes(query);
        const matchesCategory = cat === 'all' || (t.category && t.category.split(',').map(c => c.trim()).includes(cat));
        return matchesQuery && matchesCategory;
    });
    
    filtered.sort((a, b) => a.name.localeCompare(b.name)).forEach(t => {
        const opt = document.createElement('option');
        opt.value = t.name;
        opt.textContent = t.name;
        toolSelect.appendChild(opt);
    });
}

toolSelect.addEventListener('change', () => {
    const val = toolSelect.value;
    const preloadsSection = document.getElementById('preloaded-commands-section');
    const preloadsContainer = document.getElementById('preloaded-commands-container');
    
    if (!val) {
        toolInfoCard.classList.add('hidden');
        commandForm.classList.add('hidden');
        builderPlaceholder.classList.remove('hidden');
        if (preloadsSection) preloadsSection.classList.add('hidden');
        selectedTool = null;
        return;
    }
    
    selectedTool = allTools.find(t => t.name === val);
    if (selectedTool) {
        infoName.textContent = selectedTool.name;
        infoVersion.textContent = selectedTool.version ? `v${selectedTool.version}` : '';
        infoCategory.textContent = selectedTool.category || 'General';
        infoDesc.textContent = selectedTool.description || 'No description available for this package.';
        toolInfoCard.classList.remove('hidden');
        
        builderPlaceholder.classList.add('hidden');
        commandForm.classList.remove('hidden');
        buildForm(selectedTool.name);
        
        // Render preloaded commands
        const template = toolTemplates[selectedTool.name];
        if (template && template.preloads && template.preloads.length > 0) {
            preloadsContainer.innerHTML = '';
            template.preloads.forEach(preload => {
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'preload-cmd-btn';
                btn.title = preload.desc;
                
                const titleBadge = document.createElement('span');
                titleBadge.className = 'label-badge';
                titleBadge.textContent = preload.label;
                
                const cmdText = document.createTextNode(preload.desc);
                
                btn.appendChild(titleBadge);
                btn.appendChild(cmdText);
                
                btn.addEventListener('click', () => {
                    // Populate values into fields
                    template.fields.forEach(field => {
                        const input = document.getElementById(`field-${field.name}`);
                        if (input && preload.values[field.name] !== undefined) {
                            if (field.type === 'checkbox') {
                                input.checked = preload.values[field.name];
                            } else {
                                input.value = preload.values[field.name];
                            }
                        }
                    });
                    updateGeneratedCommand();
                });
                
                preloadsContainer.appendChild(btn);
            });
            if (preloadsSection) preloadsSection.classList.remove('hidden');
        } else {
            if (preloadsSection) preloadsSection.classList.add('hidden');
        }
    }
});

toolSearch.addEventListener('input', renderToolDropdown);
categoryFilter.addEventListener('change', renderToolDropdown);

function buildForm(toolName) {
    dynamicFields.innerHTML = '';
    const template = toolTemplates[toolName];
    
    if (template) {
        template.fields.forEach(field => {
            const row = document.createElement('div');
            
            if (field.type === 'checkbox') {
                row.className = 'form-checkbox-row';
                const input = document.createElement('input');
                input.type = 'checkbox';
                input.id = `field-${field.name}`;
                input.checked = field.default !== undefined ? field.default : false;
                
                const label = document.createElement('label');
                label.htmlFor = `field-${field.name}`;
                label.textContent = field.label;
                
                row.appendChild(input);
                row.appendChild(label);
                
                input.addEventListener('change', updateGeneratedCommand);
            } else {
                row.className = 'form-row';
                const label = document.createElement('label');
                label.textContent = field.label + (field.required ? " *" : "");
                row.appendChild(label);
                
                const container = document.createElement('div');
                container.className = 'input-container';
                
                if (field.type === 'select') {
                    const select = document.createElement('select');
                    select.id = `field-${field.name}`;
                    field.options.forEach(opt => {
                        const optEl = document.createElement('option');
                        optEl.value = opt.value;
                        optEl.textContent = opt.label;
                        select.appendChild(optEl);
                    });
                    if (field.default !== undefined) {
                        select.value = field.default;
                    }
                    
                    const icon = document.createElement('i');
                    icon.className = 'fa-solid fa-circle-chevron-down';
                    container.appendChild(icon);
                    container.appendChild(select);
                    
                    select.addEventListener('change', updateGeneratedCommand);
                } else {
                    const input = document.createElement('input');
                    input.type = 'text';
                    input.id = `field-${field.name}`;
                    input.placeholder = field.placeholder || '';
                    if (field.default !== undefined) {
                        input.value = field.default;
                    }
                    if (field.required) {
                        input.required = true;
                    }
                    
                    const icon = document.createElement('i');
                    icon.className = 'fa-solid fa-terminal';
                    container.appendChild(icon);
                    container.appendChild(input);
                    
                    input.addEventListener('input', updateGeneratedCommand);
                }
                row.appendChild(container);
            }
            dynamicFields.appendChild(row);
        });
    } else {
        const row = document.createElement('div');
        row.className = 'form-row';
        
        const label = document.createElement('label');
        label.textContent = "CLI Options / Arguments";
        row.appendChild(label);
        
        const container = document.createElement('div');
        container.className = 'input-container';
        
        const input = document.createElement('input');
        input.type = 'text';
        input.id = 'field-generic-args';
        input.placeholder = "e.g. -v or --help or custom parameters";
        
        const icon = document.createElement('i');
        icon.className = 'fa-solid fa-terminal';
        container.appendChild(icon);
        container.appendChild(input);
        
        input.addEventListener('input', updateGeneratedCommand);
        
        row.appendChild(container);
        dynamicFields.appendChild(row);
    }
    
    updateGeneratedCommand();
}

function updateGeneratedCommand() {
    if (!selectedTool) return;
    
    const toolName = selectedTool.name;
    const template = toolTemplates[toolName];
    
    if (template) {
        const values = {};
        template.fields.forEach(field => {
            const input = document.getElementById(`field-${field.name}`);
            if (field.type === 'checkbox') {
                values[field.name] = input.checked;
            } else {
                values[field.name] = input.value;
            }
        });
        generatedCommand.textContent = template.builder(values);
    } else {
        const argsInput = document.getElementById('field-generic-args');
        const args = argsInput ? argsInput.value.trim() : '';
        generatedCommand.textContent = `${toolName} ${args}`;
    }
}

copyCmdBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(generatedCommand.textContent);
    copyCmdBtn.innerHTML = '<i class="fa-solid fa-check term-green"></i>';
    setTimeout(() => {
        copyCmdBtn.innerHTML = '<i class="fa-regular fa-copy"></i>';
    }, 2000);
});

// Run Command Action
commandForm.addEventListener('submit', (e) => {
    e.preventDefault();
    if (commandRunning) return;
    
    const cmdStr = generatedCommand.textContent.trim();
    if (!cmdStr) return;
    
    terminalOutput.innerHTML = '';
    terminalOutput.innerHTML += `<div class="term-green">[+] Starting job execution...</div>\r\n`;
    openWindow('window-terminal');
    
    commandRunning = true;
    runBtn.disabled = true;
    runBtn.classList.add('hidden');
    stopBtn.classList.remove('hidden');
    
    terminalBadge.className = "badge term-active";
    terminalBadge.textContent = "Executing";
    
    terminalStdin.disabled = false;
    sendStdinBtn.disabled = false;
    
    socket.emit('run_command', { command: cmdStr, args: [] });
});

stopBtn.addEventListener('click', () => {
    if (!commandRunning) return;
    socket.emit('kill_process');
});

socket.on('output', (data) => {
    const cleanHtml = ansiToHtml(data);
    terminalOutput.innerHTML += cleanHtml;
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
});

socket.on('process_exit', (data) => {
    commandRunning = false;
    runBtn.disabled = false;
    runBtn.classList.remove('hidden');
    stopBtn.classList.add('hidden');
    
    terminalBadge.className = "badge term-inactive";
    terminalBadge.textContent = "Idle";
    
    terminalStdin.disabled = true;
    sendStdinBtn.disabled = true;
    terminalStdin.value = '';
});

function sendStdin() {
    const val = terminalStdin.value;
    if (!val.trim()) return;
    
    socket.emit('stdin_input', val + '\n');
    terminalOutput.innerHTML += `<span style="color: #38bdf8;">&gt; ${val}</span>\n`;
    terminalStdin.value = '';
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
}

sendStdinBtn.addEventListener('click', sendStdin);
terminalStdin.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') sendStdin();
});

copyTerminalBtn.addEventListener('click', () => {
    const text = terminalOutput.innerText;
    navigator.clipboard.writeText(text);
    copyTerminalBtn.innerHTML = '<i class="fa-solid fa-check term-green"></i> Copied';
    setTimeout(() => {
        copyTerminalBtn.innerHTML = '<i class="fa-regular fa-copy"></i> Copy Log';
    }, 2000);
});

clearTerminalBtn.addEventListener('click', () => {
    terminalOutput.innerHTML = '<div class="term-dim">Terminal screen cleared.</div>\n';
});

// Converts standard ANSI escape styles into color-coded html formatting
function ansiToHtml(ansiStr) {
    let html = ansiStr
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');

    if (html.includes('\r')) {
        const lines = html.split('\r');
        html = lines[lines.length - 1];
    }

    const ansiRegex = /\x1B\[([0-9;]*)m/g;
    let openSpans = 0;

    html = html.replace(ansiRegex, (match, codesStr) => {
        const codes = codesStr.split(';');
        let result = '';
        
        if (codes.includes('0') || codesStr === '') {
            result += '</span>'.repeat(openSpans);
            openSpans = 0;
        }

        for (const code of codes) {
            if (code === '1') {
                result += '<span style="font-weight: bold;">';
                openSpans++;
            } else if (code >= '30' && code <= '37') {
                const colors = ['#1e293b', '#ef4444', '#10b981', '#f59e0b', '#3b82f6', '#a855f7', '#06b6d4', '#f8fafc'];
                result += `<span style="color: ${colors[code - 30]};">`;
                openSpans++;
            } else if (code >= '90' && code <= '97') {
                const lightColors = ['#64748b', '#fca5a5', '#86efac', '#fde047', '#93c5fd', '#d8b4fe', '#67e8f9', '#ffffff'];
                result += `<span style="color: ${lightColors[code - 90]};">`;
                openSpans++;
            }
        }
        return result;
    });

    return html + '</span>'.repeat(openSpans);
}

// -------------------------------------------------------------
// 8. AFOS PACKAGES MANAGER
// -------------------------------------------------------------
const afosUpdateBtn = document.getElementById('afos-update-btn');
const afosInstallInput = document.getElementById('afos-install-input');
const afosInstallBtn = document.getElementById('afos-install-btn');
const afosOpStatus = document.getElementById('afos-op-status');
const packageListBody = document.getElementById('package-list-body');

afosUpdateBtn.addEventListener('click', async () => {
    afosUpdateBtn.disabled = true;
    afosUpdateBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Updating...';
    try {
        const res = await fetch('/api/afos/update', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            alert("AFOS tool repositories updated successfully!");
            loadTools();
        } else {
            alert(`Error: ${data.error}`);
        }
    } catch (e) {
        alert(`API Error: ${e.message}`);
    } finally {
        afosUpdateBtn.disabled = false;
        afosUpdateBtn.innerHTML = '<i class="fa-solid fa-rotate"></i> Update Tool Repositories';
    }
});

afosInstallBtn.addEventListener('click', async () => {
    const toolName = afosInstallInput.value.trim();
    if (!toolName) return;
    
    afosInstallBtn.disabled = true;
    afosInstallBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
    afosOpStatus.classList.remove('hidden');
    afosOpStatus.textContent = `[+] Requesting installation of ${toolName}...\n`;
    
    try {
        const res = await fetch('/api/afos/install', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ toolName })
        });
        const data = await res.json();
        if (data.success) {
            afosOpStatus.textContent += `[+] Installation Success:\n${data.stdout}`;
            loadTools();
            afosInstallInput.value = '';
        } else {
            afosOpStatus.textContent += `[!] Error:\n${data.error}\n${data.stderr || ''}`;
        }
    } catch (e) {
        afosOpStatus.textContent += `[!] Exception: ${e.message}`;
    } finally {
        afosInstallBtn.disabled = false;
        afosInstallBtn.innerHTML = 'Install';
    }
});

function renderPackagesTable() {
    packageListBody.innerHTML = '';
    if (allTools.length === 0) {
        packageListBody.innerHTML = '<tr><td colspan="3" class="text-center">No tools loaded. Run Update.</td></tr>';
        return;
    }
    allTools.sort((a, b) => a.name.localeCompare(b.name)).forEach(t => {
        const row = document.createElement('tr');
        const nameTd = document.createElement('td');
        nameTd.style.fontWeight = 'bold';
        nameTd.style.color = 'var(--primary)';
        nameTd.textContent = t.name;
        const verTd = document.createElement('td');
        verTd.textContent = t.version || '-';
        const catTd = document.createElement('td');
        catTd.textContent = t.category || 'General';
        
        row.appendChild(nameTd);
        row.appendChild(verTd);
        row.appendChild(catTd);
        packageListBody.appendChild(row);
    });
}

// -------------------------------------------------------------
// 9. REMOTE INTERACTIVE SSH CONSOLE CLIENT
// -------------------------------------------------------------
const sshHost = document.getElementById('ssh-host');
const sshPort = document.getElementById('ssh-port');
const sshUser = document.getElementById('ssh-user');
const sshPass = document.getElementById('ssh-pass');
const sshConnectBtn = document.getElementById('ssh-connect-btn');
const sshDisconnectBtn = document.getElementById('ssh-disconnect-btn');
const sshOutput = document.getElementById('ssh-output');
const sshStdin = document.getElementById('ssh-stdin');
const sshSendBtn = document.getElementById('ssh-send-stdin-btn');

sshConnectBtn.addEventListener('click', () => {
    if (sshConnected) return;
    
    const host = sshHost.value.trim();
    const port = sshPort.value.trim();
    const username = sshUser.value.trim();
    const password = sshPass.value.trim();

    if (!host || !username) {
        alert("Host and Username are required fields.");
        return;
    }

    sshOutput.innerHTML = '';
    sshOutput.innerHTML += '<div class="term-green">[+] Connecting via Socket.io bridge...</div>\n';
    socket.emit('ssh_connect', { host, port, username, password });
});

sshDisconnectBtn.addEventListener('click', () => {
    socket.emit('ssh_disconnect');
});

socket.on('ssh_connected', () => {
    sshConnected = true;
    sshConnectBtn.classList.add('hidden');
    sshDisconnectBtn.classList.remove('hidden');
    sshStdin.disabled = false;
    sshSendBtn.disabled = false;
});

socket.on('ssh_output', (data) => {
    sshOutput.innerHTML += ansiToHtml(data);
    sshOutput.scrollTop = sshOutput.scrollHeight;
});

socket.on('ssh_closed', () => {
    sshConnected = false;
    sshConnectBtn.classList.remove('hidden');
    sshDisconnectBtn.classList.add('hidden');
    sshStdin.disabled = true;
    sshSendBtn.disabled = true;
    sshStdin.value = '';
});

function sendSshStdin() {
    const val = sshStdin.value;
    if (!val) return;
    socket.emit('ssh_input', val + '\n');
    sshStdin.value = '';
}

sshSendBtn.addEventListener('click', sendSshStdin);
sshStdin.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') sendSshStdin();
});

// -------------------------------------------------------------
// 10. TAILSCALE CONFIGURATION CLIENT
// -------------------------------------------------------------
const tsStateBadge = document.getElementById('ts-state-badge');
const tsNodeName = document.getElementById('ts-node-name');
const tsNodeIp = document.getElementById('ts-node-ip');
const tsDaemonBadge = document.getElementById('ts-daemon-badge');
const tsStartDaemonBtn = document.getElementById('ts-start-daemon-btn');
const tsUpBtn = document.getElementById('ts-up-btn');
const tsDownBtn = document.getElementById('ts-down-btn');
const tsLogoutBtn = document.getElementById('ts-logout-btn');
const tsAuthPanel = document.getElementById('ts-auth-panel');
const tsAuthLink = document.getElementById('ts-auth-link');
const tsPeersBody = document.getElementById('ts-peers-body');

async function updateTailscaleStatus() {
    try {
        const response = await fetch('/api/tailscale/status');
        const data = await response.json();
        
        if (data.daemonRunning) {
            tsDaemonBadge.textContent = "Active (Userspace)";
            tsDaemonBadge.className = "val text-green";
            tsStartDaemonBtn.classList.add('hidden');
            tsUpBtn.disabled = false;
            tsDownBtn.disabled = false;
            tsLogoutBtn.disabled = false;
            
            tsStateBadge.textContent = data.backendState;
            if (data.backendState === "Running") {
                tsStateBadge.className = "val badge category-badge";
                tsNodeName.textContent = data.selfName || "-";
                tsNodeIp.textContent = data.ips ? data.ips.join(', ') : "-";
                tsAuthPanel.classList.add('hidden');
            } else if (data.backendState === "NeedsLogin") {
                tsStateBadge.className = "val badge warning";
                tsNodeName.textContent = "-";
                tsNodeIp.textContent = "-";
                
                if (data.authUrl) {
                    tsAuthPanel.classList.remove('hidden');
                    tsAuthLink.href = data.authUrl;
                    tsAuthLink.textContent = data.authUrl;
                } else {
                    tsAuthPanel.classList.add('hidden');
                }
            } else {
                tsStateBadge.className = "val badge warning";
                tsNodeName.textContent = "-";
                tsNodeIp.textContent = "-";
                tsAuthPanel.classList.add('hidden');
            }
            
            renderTsPeers(data.peers);
        } else {
            tsDaemonBadge.textContent = "Stopped / Inactive";
            tsDaemonBadge.className = "val text-danger";
            tsStateBadge.textContent = "Offline";
            tsStateBadge.className = "val badge term-inactive";
            tsNodeName.textContent = "-";
            tsNodeIp.textContent = "-";
            tsStartDaemonBtn.classList.remove('hidden');
            tsUpBtn.disabled = true;
            tsDownBtn.disabled = true;
            tsLogoutBtn.disabled = true;
            tsAuthPanel.classList.add('hidden');
            tsPeersBody.innerHTML = '<tr><td colspan="4" class="text-center text-danger">Daemon offline. Start Daemon first.</td></tr>';
        }
    } catch (e) {
        console.error("Tailscale status polling error:", e);
    }
}

function renderTsPeers(peers) {
    if (!peers || peers.length === 0) {
        tsPeersBody.innerHTML = '<tr><td colspan="4" class="text-center">No peers connected. Connect VPN to view devices.</td></tr>';
        return;
    }
    
    tsPeersBody.innerHTML = '';
    peers.forEach(p => {
        const row = document.createElement('tr');
        
        const nameTd = document.createElement('td');
        nameTd.style.fontWeight = 'bold';
        nameTd.textContent = p.name;
        
        const ipTd = document.createElement('td');
        ipTd.textContent = p.ip;
        
        const osTd = document.createElement('td');
        osTd.textContent = p.os || "linux";
        
        const statusTd = document.createElement('td');
        statusTd.innerHTML = p.online 
            ? '<span class="text-green"><i class="fa-solid fa-circle"></i> Online</span>' 
            : '<span class="term-dim"><i class="fa-regular fa-circle"></i> Offline</span>';
            
        row.appendChild(nameTd);
        row.appendChild(ipTd);
        row.appendChild(osTd);
        row.appendChild(statusTd);
        tsPeersBody.appendChild(row);
    });
}

tsStartDaemonBtn.addEventListener('click', async () => {
    tsStartDaemonBtn.disabled = true;
    try {
        await fetch('/api/tailscale/start', { method: 'POST' });
        setTimeout(updateTailscaleStatus, 2000);
    } catch (e) {
        alert(e.message);
    } finally {
        tsStartDaemonBtn.disabled = false;
    }
});

tsUpBtn.addEventListener('click', async () => {
    tsUpBtn.disabled = true;
    try {
        await fetch('/api/tailscale/up', { method: 'POST' });
        setTimeout(updateTailscaleStatus, 2000);
    } catch (e) {
        alert(e.message);
    } finally {
        tsUpBtn.disabled = false;
    }
});

tsDownBtn.addEventListener('click', async () => {
    tsDownBtn.disabled = true;
    try {
        await fetch('/api/tailscale/down', { method: 'POST' });
        setTimeout(updateTailscaleStatus, 1500);
    } catch (e) {
        alert(e.message);
    } finally {
        tsDownBtn.disabled = false;
    }
});

tsLogoutBtn.addEventListener('click', async () => {
    if (confirm("Disconnect and clear credentials for Tailscale VPN?")) {
        tsLogoutBtn.disabled = true;
        try {
            await fetch('/api/tailscale/logout', { method: 'POST' });
            setTimeout(updateTailscaleStatus, 2000);
        } catch (e) {
            alert(e.message);
        } finally {
            tsLogoutBtn.disabled = false;
        }
    }
});

// -------------------------------------------------------------
// 11. MEDIA SCREENCAST & VIDEO RECORDER (WEBRTC)
// -------------------------------------------------------------
const scrStartBtn = document.getElementById('screencast-start-btn');
const scrStopBtn = document.getElementById('screencast-stop-btn');
const scrRecStartBtn = document.getElementById('screencast-record-start-btn');
const scrRecStopBtn = document.getElementById('screencast-record-stop-btn');
const scrVideo = document.getElementById('screencast-video');
const scrPlaceholder = document.getElementById('screencast-placeholder');
const scrStatus = document.getElementById('screencast-status');

scrStartBtn.addEventListener('click', async () => {
    try {
        screencastStream = await navigator.mediaDevices.getDisplayMedia({
            video: { cursor: "always" },
            audio: false
        });
        
        scrVideo.srcObject = screencastStream;
        scrVideo.classList.remove('hidden');
        scrPlaceholder.classList.add('hidden');
        
        scrStartBtn.classList.add('hidden');
        scrStopBtn.classList.remove('hidden');
        scrRecStartBtn.classList.remove('hidden');
        
        scrStatus.textContent = "Streaming Live";
        scrStatus.className = "badge term-active";
        
        screencastStream.getVideoTracks()[0].onended = () => {
            stopScreencast();
        };
    } catch (e) {
        console.error("Display media error:", e);
    }
});

function stopScreencast() {
    if (mediaRecorder && mediaRecorder.state !== 'inactive') {
        stopRecording();
    }
    
    if (screencastStream) {
        screencastStream.getTracks().forEach(track => track.stop());
        screencastStream = null;
    }
    
    scrVideo.srcObject = null;
    scrVideo.classList.add('hidden');
    scrPlaceholder.classList.remove('hidden');
    
    scrStartBtn.classList.remove('hidden');
    scrStopBtn.classList.add('hidden');
    scrRecStartBtn.classList.add('hidden');
    scrRecStopBtn.classList.add('hidden');
    
    scrStatus.textContent = "Inactive";
    scrStatus.className = "badge term-inactive";
}

scrStopBtn.addEventListener('click', stopScreencast);

scrRecStartBtn.addEventListener('click', () => {
    if (!screencastStream) return;
    
    recordedChunks = [];
    mediaRecorder = new MediaRecorder(screencastStream, { mimeType: 'video/webm; codecs=vp9' });
    
    mediaRecorder.ondataavailable = (event) => {
        if (event.data.size > 0) {
            recordedChunks.push(event.data);
        }
    };
    
    mediaRecorder.onstop = () => {
        const blob = new Blob(recordedChunks, { type: 'video/webm' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `screencast-${new Date().toISOString().slice(0,19).replace(/:/g,'-')}.webm`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };
    
    mediaRecorder.start();
    
    scrRecStartBtn.classList.add('hidden');
    scrRecStopBtn.classList.remove('hidden');
    scrStatus.textContent = "Recording";
    scrStatus.className = "badge danger";
});

function stopRecording() {
    if (mediaRecorder && mediaRecorder.state !== 'inactive') {
        mediaRecorder.stop();
    }
    scrRecStartBtn.classList.remove('hidden');
    scrRecStopBtn.classList.add('hidden');
    scrStatus.textContent = "Streaming Live";
    scrStatus.className = "badge term-active";
}

scrRecStopBtn.addEventListener('click', stopRecording);

// -------------------------------------------------------------
// 12. DYNAMIC LOCAL & CLOUD AI CYBER ASSISTANT CLIENT
// -------------------------------------------------------------
const aiProvider = document.getElementById('ai-provider');
const aiApikey = document.getElementById('ai-apikey');
const aiEndpoint = document.getElementById('ai-endpoint');
const aiModel = document.getElementById('ai-model');
const aiTemp = document.getElementById('ai-temp');
const aiTempVal = document.getElementById('ai-temp-val');
const aiSystemPrompt = document.getElementById('ai-system-prompt');
const aiChatThread = document.getElementById('ai-chat-thread');
const aiStdin = document.getElementById('ai-stdin');
const aiSendBtn = document.getElementById('ai-send-btn');

// Local storage keys for parameters cache
const STORAGE_KEYS = {
    provider: 'andrax_ai_provider',
    apiKey: 'andrax_ai_apikey',
    endpoint: 'andrax_ai_endpoint',
    model: 'andrax_ai_model',
    systemPrompt: 'andrax_ai_system_prompt',
    temperature: 'andrax_ai_temperature'
};

// Toggle field visibilities based on AI provider
function adjustAiFields() {
    const provider = aiProvider.value;
    const keyGroup = document.getElementById('ai-apikey-group');
    const endpointGroup = document.getElementById('ai-endpoint-group');
    
    // Hide/show endpoints and keys appropriately
    if (provider === 'openai') {
        keyGroup.classList.remove('hidden');
        endpointGroup.classList.add('hidden');
        aiModel.placeholder = 'e.g. gpt-4o';
    } else if (provider === 'anthropic') {
        keyGroup.classList.remove('hidden');
        endpointGroup.classList.add('hidden');
        aiModel.placeholder = 'e.g. claude-3-5-sonnet-20240620';
    } else if (provider === 'gemini') {
        keyGroup.classList.remove('hidden');
        endpointGroup.classList.add('hidden');
        aiModel.placeholder = 'e.g. gemini-1.5-flash';
    } else if (provider === 'ollama') {
        keyGroup.classList.add('hidden');
        endpointGroup.classList.remove('hidden');
        aiModel.placeholder = 'e.g. llama3';
        if (!aiEndpoint.value) aiEndpoint.value = 'http://localhost:11434';
    } else if (provider === 'custom') {
        keyGroup.classList.remove('hidden');
        endpointGroup.classList.remove('hidden');
        aiModel.placeholder = 'e.g. custom-model';
    }
}

aiProvider.addEventListener('change', () => {
    adjustAiFields();
    localStorage.setItem(STORAGE_KEYS.provider, aiProvider.value);
});

// Sync values to LocalStorage on change
aiApikey.addEventListener('input', () => localStorage.setItem(STORAGE_KEYS.apiKey, aiApikey.value));
aiEndpoint.addEventListener('input', () => localStorage.setItem(STORAGE_KEYS.endpoint, aiEndpoint.value));
aiModel.addEventListener('input', () => localStorage.setItem(STORAGE_KEYS.model, aiModel.value));
aiSystemPrompt.addEventListener('input', () => localStorage.setItem(STORAGE_KEYS.systemPrompt, aiSystemPrompt.value));

aiTemp.addEventListener('input', () => {
    const val = (aiTemp.value / 100).toFixed(2);
    aiTempVal.textContent = val;
    localStorage.setItem(STORAGE_KEYS.temperature, val);
});

// Load AI cache on boot
function loadAiCache() {
    if (localStorage.getItem(STORAGE_KEYS.provider)) aiProvider.value = localStorage.getItem(STORAGE_KEYS.provider);
    if (localStorage.getItem(STORAGE_KEYS.apiKey)) aiApikey.value = localStorage.getItem(STORAGE_KEYS.apiKey);
    if (localStorage.getItem(STORAGE_KEYS.endpoint)) aiEndpoint.value = localStorage.getItem(STORAGE_KEYS.endpoint);
    if (localStorage.getItem(STORAGE_KEYS.model)) aiModel.value = localStorage.getItem(STORAGE_KEYS.model);
    if (localStorage.getItem(STORAGE_KEYS.systemPrompt)) aiSystemPrompt.value = localStorage.getItem(STORAGE_KEYS.systemPrompt);
    if (localStorage.getItem(STORAGE_KEYS.temperature)) {
        const val = localStorage.getItem(STORAGE_KEYS.temperature);
        aiTemp.value = Math.round(val * 100);
        aiTempVal.textContent = val;
    }
    adjustAiFields();
}

// Send chat message to AI assistant
async function sendAiMessage() {
    const text = aiStdin.value.trim();
    if (!text) return;
    
    // Add user message to UI and thread
    appendAiMessage('user', text);
    aiThread.push({ role: 'user', content: text });
    
    aiStdin.value = '';
    aiStdin.disabled = true;
    aiSendBtn.disabled = true;
    
    // Add a loading indicator message bubble
    const loadingBubble = appendAiMessage('assistant', '<i class="fa-solid fa-spinner fa-spin"></i> Processing request...');
    
    // Prepare API body
    const body = {
        provider: aiProvider.value,
        apiKey: aiApikey.value.trim(),
        endpoint: aiEndpoint.value.trim(),
        model: aiModel.value.trim(),
        temperature: (aiTemp.value / 100).toFixed(2),
        systemPrompt: aiSystemPrompt.value.trim(),
        messages: aiThread
    };
    
    try {
        const response = await fetch('/api/ai/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        
        const data = await response.json();
        
        // Remove loading bubble
        loadingBubble.remove();
        
        if (data.success) {
            appendAiMessage('assistant', data.response);
            aiThread.push({ role: 'assistant', content: data.response });
        } else {
            appendAiMessage('assistant', `<span class="text-danger">[!] API Error: ${data.error}</span>`);
        }
    } catch (e) {
        loadingBubble.remove();
        appendAiMessage('assistant', `<span class="text-danger">[!] Network Exception: ${e.message}</span>`);
    } finally {
        aiStdin.disabled = false;
        aiSendBtn.disabled = false;
        aiStdin.focus();
    }
}

function appendAiMessage(role, content) {
    const bubble = document.createElement('div');
    bubble.className = `ai-message ${role}`;
    
    const sender = role === 'user' ? 'USER' : 'CYBER_ASSISTANT';
    const tagColor = role === 'user' ? '#60a5fa' : 'var(--primary)';
    
    bubble.innerHTML = `
        <span class="sender-tag" style="color:${tagColor}; font-weight:bold; font-family:var(--font-logo); font-size:0.72rem; display:block; margin-bottom:4px;">[+] ${sender}</span>
        <p style="font-size:0.8rem; line-height:1.45; color:var(--text-color); white-space:pre-wrap;">${content}</p>
    `;
    
    aiChatThread.appendChild(bubble);
    aiChatThread.scrollTop = aiChatThread.scrollHeight;
    return bubble;
}

aiSendBtn.addEventListener('click', sendAiMessage);
aiStdin.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') sendAiMessage();
});

// -------------------------------------------------------------
// 13. SYSTEM INFO REST CALLS
// -------------------------------------------------------------
async function updateSysInfo() {
    try {
        const response = await fetch('/api/sysinfo');
        const data = await response.json();

        const uptimeEl = document.getElementById('sys-uptime');
        const memoryEl = document.getElementById('sys-memory');
        const diskEl = document.getElementById('sys-disk');
        const interfacesEl = document.getElementById('sys-interfaces');

        if (uptimeEl) uptimeEl.textContent = data.uptime;
        if (memoryEl) memoryEl.textContent = data.memory;
        if (diskEl) diskEl.textContent = data.disk;

        if (interfacesEl) {
            const ifaceList = data.interfaces && data.interfaces.length > 0
                ? data.interfaces.join(', ')
                : 'None detected';
            interfacesEl.textContent = ifaceList;
        }
    } catch (e) {
        console.error("Failed to fetch system monitor specs:", e);
    }
}

// -------------------------------------------------------------
// 14. ON DESKTOP INITIALIZATION & STARTUP RUN
// -------------------------------------------------------------
window.addEventListener('DOMContentLoaded', () => {
    runTrayClock();
    runMatrixRain();
    
    document.querySelectorAll('.desktop-window').forEach(w => {
        initDraggability(w);
        initResizability(w);
        setupWindowControlListeners(w);
    });

    document.querySelectorAll('.shortcut-icon').forEach(sc => {
        sc.addEventListener('click', () => {
            const targetWinId = sc.getAttribute('data-window');
            openWindow(targetWinId);
        });
    });

    document.querySelectorAll('.menu-item').forEach(mi => {
        mi.addEventListener('click', () => {
            const targetWinId = mi.getAttribute('data-window');
            openWindow(targetWinId);
            startMenu.classList.add('hidden');
            startBtn.classList.remove('active');
            startMenuOpen = false;
        });
    });

    window.addEventListener('resize', () => {
        resizeMatrixCanvas();
        adjustDesktopSize();
    });

    loadTools();
    adjustDesktopSize();
    updateSysInfo();
    updateTailscaleStatus();
    loadAiCache();
    
    syncTaskbarItems();
    
    setInterval(updateSysInfo, 5000);
    setInterval(updateTailscaleStatus, 4000);
});
