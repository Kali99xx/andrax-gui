const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const { exec, spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const { Client } = require('ssh2');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const PORT = 8080;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let cachedTools = [];

function stripAnsi(str) {
    return str.replace(/[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g, '');
}

// Parse afos list command
function parseAfosList() {
    return new Promise((resolve) => {
        exec('sudo afos --list', (err, stdout, stderr) => {
            if (err) {
                console.error("Error executing afos --list:", err);
                return resolve([]);
            }
            
            const tools = [];
            const lines = stdout.split('\n');
            // Pattern: [ name ] [ version ] [ description ] [ category ]
            const regex = /^\[\s*([^\]\s]+)\s*\]\s*\[\s*([^\]]+)\s*\]\s*\[\s*([^\]]+)\s*\]\s*\[\s*([^\]]+)\s*\]/;
            
            for (const line of lines) {
                const match = line.match(regex);
                if (match) {
                    tools.push({
                        name: stripAnsi(match[1].trim()),
                        version: stripAnsi(match[2].trim()),
                        description: stripAnsi(match[3].trim()),
                        category: stripAnsi(match[4].trim())
                    });
                }
            }
            resolve(tools);
        });
    });
}

const systemTools = [
    {
        name: "wifite",
        version: "2.9.9b0",
        description: "Automated wireless auditor and attack tool",
        category: "Wireless Hacking"
    },
    {
        name: "nikto",
        version: "2.5.0",
        description: "Web server vulnerability and configuration scanner",
        category: "Web Site Hacking"
    },
    {
        name: "ping",
        version: "1.0",
        description: "Send ICMP ECHO_REQUEST to network hosts",
        category: "Scanning, Network Hacking"
    },
    {
        name: "iw",
        version: "1.0",
        description: "Show and manipulate wireless devices and configuration",
        category: "Wireless Hacking"
    },
    {
        name: "ip",
        version: "1.0",
        description: "Show and manipulate routing, network devices, and interfaces",
        category: "Network Hacking"
    }
];

// Start Tailscale daemon autonomously on start if not running
function startTailscaleDaemon() {
    exec('pgrep tailscaled', (err, stdout) => {
        if (err || !stdout) {
            console.log("[Tailscale] Starting tailscaled daemon in userspace mode...");
            exec('sudo mkdir -p /var/lib/tailscale /var/run/tailscale && sudo rm -f /var/run/tailscale/tailscaled.sock && sudo nohup tailscaled --tun=userspace-networking --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock > /tmp/tailscaled.log 2>&1 &', (daemonErr) => {
                if (daemonErr) console.error("[Tailscale] Error launching daemon:", daemonErr);
            });
        } else {
            console.log("[Tailscale] tailscaled daemon is already running.");
        }
    });
}

// Boot up tasks
parseAfosList().then(tools => {
    cachedTools = tools;
    console.log(`Loaded ${cachedTools.length} tools from afos database.`);
    startTailscaleDaemon();
});

// REST API Endpoints
app.get('/api/tools', async (req, res) => {
    if (cachedTools.length === 0) {
        cachedTools = await parseAfosList();
    }
    const merged = [...cachedTools];
    systemTools.forEach(sysTool => {
        if (!merged.some(t => t.name === sysTool.name)) {
            merged.push(sysTool);
        }
    });
    res.json(merged);
});

app.get('/api/sysinfo', (req, res) => {
    const sysinfo = {
        uptime: 'N/A',
        memory: 'N/A',
        disk: 'N/A',
        interfaces: []
    };

    exec('uptime -p', (err, stdout) => {
        if (!err && stdout) sysinfo.uptime = stdout.trim();

        exec("free -m | awk '/Mem:/ {print $3 \"MB / \" $2 \"MB\"}'", (err, stdout) => {
            if (!err && stdout) sysinfo.memory = stdout.trim();

            exec("df -h / | awk 'NR==2 {print $3 \" / \" $2 \" (\" $5 \" used)\"}'", (err, stdout) => {
                if (!err && stdout) sysinfo.disk = stdout.trim();

                exec('iw dev | grep Interface | awk \'{print $2}\'', (err, stdout) => {
                    if (!err && stdout) {
                        sysinfo.interfaces = stdout.trim().split('\n').filter(Boolean);
                    }
                    res.json(sysinfo);
                });
            });
        });
    });
});

app.post('/api/interface/monitor-mode', (req, res) => {
    const { iface, enable } = req.body;
    if (!iface || !/^[a-zA-Z0-9_\-]+$/.test(iface)) {
        return res.status(400).json({ error: "Invalid interface name" });
    }

    const command = enable 
        ? `sudo airmon-ng start ${iface}` 
        : `sudo airmon-ng stop ${iface}`;

    console.log(`[MonitorMode] Executing: ${command}`);
    exec(command, (err, stdout, stderr) => {
        if (err) {
            console.error(`[MonitorMode] Error: ${err.message}`);
            return res.status(500).json({ error: err.message, stderr });
        }
        res.json({ success: true, stdout });
    });
});

app.post('/api/afos/update', (req, res) => {
    exec('sudo afos --update-all || sudo afos --update', (err, stdout, stderr) => {
        if (err) {
            return res.status(500).json({ error: err.message, stderr });
        }
        parseAfosList().then(tools => {
            cachedTools = tools;
            res.json({ success: true, stdout, toolsCount: cachedTools.length });
        });
    });
});

app.post('/api/afos/install', (req, res) => {
    const { toolName } = req.body;
    if (!toolName || !/^[a-zA-Z0-9_\-]+$/.test(toolName)) {
        return res.status(400).json({ error: "Invalid tool name" });
    }
    exec(`sudo afos --install ${toolName}`, (err, stdout, stderr) => {
        if (err) {
            return res.status(500).json({ error: err.message, stderr });
        }
        res.json({ success: true, stdout });
    });
});

// TAILSCALE REST API
app.get('/api/tailscale/status', (req, res) => {
    exec('pgrep tailscaled', (err, stdout) => {
        const daemonRunning = !err && stdout.trim().length > 0;
        if (!daemonRunning) {
            return res.json({ daemonRunning: false, backendState: "Stopped", peers: [], authUrl: "" });
        }

        exec('sudo tailscale status --json', (errStatus, stdoutStatus) => {
            if (errStatus) {
                return res.json({ daemonRunning: true, backendState: "Connecting", peers: [], authUrl: "" });
            }

            try {
                const status = JSON.parse(stdoutStatus);
                let authUrl = "";
                if (status.BackendState === "NeedsLogin" || status.BackendState === "NoState") {
                    if (fs.existsSync('/tmp/tailscale-up.log')) {
                        const content = fs.readFileSync('/tmp/tailscale-up.log', 'utf8');
                        const match = content.match(/https:\/\/login\.tailscale\.com\/a\/[a-zA-Z0-9]+/);
                        if (match) {
                            authUrl = match[0];
                        }
                    }
                }

                const peers = [];
                if (status.Peer) {
                    Object.keys(status.Peer).forEach(key => {
                        const p = status.Peer[key];
                        peers.push({
                            name: p.HostName,
                            ip: p.TailscaleIPs ? p.TailscaleIPs[0] : "N/A",
                            online: p.Online,
                            active: p.Active,
                            os: p.OS
                        });
                    });
                }

                res.json({
                    daemonRunning: true,
                    backendState: status.BackendState,
                    authUrl: authUrl,
                    ips: status.Self ? status.Self.TailscaleIPs : null,
                    selfName: status.Self ? status.Self.HostName : "",
                    peers: peers
                });
            } catch (e) {
                res.json({ daemonRunning: true, backendState: "ParseError", peers: [], authUrl: "", error: e.message });
            }
        });
    });
});

app.post('/api/tailscale/start', (req, res) => {
    console.log("[Tailscale] Manual start-daemon trigger");
    exec('sudo mkdir -p /var/lib/tailscale /var/run/tailscale && sudo rm -f /var/run/tailscale/tailscaled.sock && sudo nohup tailscaled --tun=userspace-networking --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock > /tmp/tailscaled.log 2>&1 &', (err) => {
        if (err) {
            return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true });
    });
});

app.post('/api/tailscale/up', (req, res) => {
    console.log("[Tailscale] Triggering tailscale up...");
    if (fs.existsSync('/tmp/tailscale-up.log')) {
        fs.writeFileSync('/tmp/tailscale-up.log', '');
    }
    exec('sudo nohup tailscale up --reset > /tmp/tailscale-up.log 2>&1 &', (err) => {
        if (err) {
            return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true });
    });
});

app.post('/api/tailscale/down', (req, res) => {
    console.log("[Tailscale] Triggering tailscale down...");
    exec('sudo tailscale down', (err, stdout, stderr) => {
        if (err) {
            return res.status(500).json({ success: false, error: err.message, stderr });
        }
        res.json({ success: true, stdout });
    });
});

app.post('/api/tailscale/logout', (req, res) => {
    console.log("[Tailscale] Triggering tailscale logout...");
    exec('sudo tailscale logout', (err, stdout, stderr) => {
        if (err) {
            return res.status(500).json({ success: false, error: err.message, stderr });
        }
        if (fs.existsSync('/tmp/tailscale-up.log')) {
            fs.writeFileSync('/tmp/tailscale-up.log', '');
        }
        res.json({ success: true, stdout });
    });
});

// MULTI-PROVIDER LOCAL & CLOUD AI COMPATIBLE CHAT API
app.post('/api/ai/chat', async (req, res) => {
    const { provider, apiKey, endpoint, model, temperature, systemPrompt, messages } = req.body;
    
    if (!messages || !Array.isArray(messages)) {
        return res.status(400).json({ success: false, error: "Messages array is required." });
    }

    try {
        let aiResponseText = "";
        const tempVal = parseFloat(temperature) !== undefined ? parseFloat(temperature) : 0.7;

        if (provider === 'openai') {
            const resp = await fetch('https://api.openai.com/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${apiKey}`
                },
                body: JSON.stringify({
                    model: model || 'gpt-4o',
                    messages: [{ role: 'system', content: systemPrompt }, ...messages],
                    temperature: tempVal
                })
            });
            if (!resp.ok) {
                const errText = await resp.text();
                throw new Error(`OpenAI error: ${resp.status} ${errText}`);
            }
            const data = await resp.json();
            aiResponseText = data.choices[0].message.content;

        } else if (provider === 'anthropic') {
            const resp = await fetch('https://api.anthropic.com/v1/messages', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': apiKey,
                    'anthropic-version': '2023-06-01'
                },
                body: JSON.stringify({
                    model: model || 'claude-3-5-sonnet-20240620',
                    system: systemPrompt,
                    messages: messages.filter(m => m.role !== 'system'),
                    temperature: tempVal,
                    max_tokens: 2048
                })
            });
            if (!resp.ok) {
                const errText = await resp.text();
                throw new Error(`Anthropic error: ${resp.status} ${errText}`);
            }
            const data = await resp.json();
            aiResponseText = data.content[0].text;

        } else if (provider === 'gemini') {
            const cleanModel = model || 'gemini-1.5-flash';
            const resp = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${cleanModel}:generateContent?key=${apiKey}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    contents: messages.map(m => ({
                        role: m.role === 'assistant' ? 'model' : 'user',
                        parts: [{ text: m.content }]
                    })),
                    systemInstruction: systemPrompt ? {
                        parts: [{ text: systemPrompt }]
                    } : undefined,
                    generationConfig: {
                        temperature: tempVal
                    }
                })
            });
            if (!resp.ok) {
                const errText = await resp.text();
                throw new Error(`Gemini error: ${resp.status} ${errText}`);
            }
            const data = await resp.json();
            aiResponseText = data.candidates[0].content.parts[0].text;

        } else if (provider === 'ollama') {
            const cleanUrl = (endpoint || 'http://localhost:11434').replace(/\/$/, '');
            const resp = await fetch(`${cleanUrl}/api/chat`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: model || 'llama3',
                    messages: [{ role: 'system', content: systemPrompt }, ...messages],
                    options: {
                        temperature: tempVal
                    },
                    stream: false
                })
            });
            if (!resp.ok) {
                const errText = await resp.text();
                throw new Error(`Ollama error: ${resp.status} ${errText}`);
            }
            const data = await resp.json();
            aiResponseText = data.message.content;

        } else if (provider === 'custom') {
            const resp = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': apiKey ? `Bearer ${apiKey}` : undefined
                },
                body: JSON.stringify({
                    model: model,
                    messages: [{ role: 'system', content: systemPrompt }, ...messages],
                    temperature: tempVal
                })
            });
            if (!resp.ok) {
                const errText = await resp.text();
                throw new Error(`Custom endpoint error: ${resp.status} ${errText}`);
            }
            const data = await resp.json();
            aiResponseText = data.choices[0].message.content;
        } else {
            throw new Error(`Unsupported provider: ${provider}`);
        }

        res.json({ success: true, response: aiResponseText });

    } catch (e) {
        console.error("[AI Chat API Error]:", e);
        res.status(500).json({ success: false, error: e.message });
    }
});

// WebSockets for interactive shell and interactive SSH
io.on('connection', (socket) => {
    let runningProcess = null;
    let sshClient = null;
    let sshShell = null;

    console.log('Client connected:', socket.id);

    // Dynamic standard process executor
    socket.on('run_command', (data) => {
        if (runningProcess) {
            socket.emit('output', '\r\n\x1B[1;31m[!] Error: A command is already running.\x1B[0m\r\n');
            return;
        }

        const { command, args } = data;
        
        const baseCmd = command.split(' ').find(w => w !== 'sudo' && w !== '');
        const isWhitelisted = cachedTools.some(t => t.name === baseCmd) || 
                              systemTools.some(t => t.name === baseCmd) ||
                              ['ping', 'ip', 'iw', 'ifconfig', 'wifite', 'afos', 'nmap', 'hydra', 'thc-hydra', 'nikto', 'tailscale'].includes(baseCmd);
        
        if (!isWhitelisted) {
            socket.emit('output', `\r\n\x1B[1;31m[!] Execution Blocked: Command "${baseCmd}" is not whitelisted.\x1B[0m\r\n`);
            return;
        }

        console.log(`Executing: ${command} ${args.join(' ')}`);
        socket.emit('output', `\x1B[1;32m[+] Starting:\x1B[0m ${command} ${args.join(' ')}\r\n\r\n`);

        const cmdParts = command.split(' ');
        let executable = cmdParts[0];
        let fullArgs = cmdParts.slice(1).concat(args);

        if (executable === 'sudo') {
            executable = 'sudo';
        } else {
            fullArgs = ['-c', `${command} ${args.join(' ')}`];
            executable = 'bash';
        }

        try {
            runningProcess = spawn(executable, fullArgs, {
                env: { ...process.env, PATH: '/opt/ANDRAX/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' },
                shell: true
            });

            runningProcess.stdout.on('data', (data) => {
                socket.emit('output', data.toString());
            });

            runningProcess.stderr.on('data', (data) => {
                socket.emit('output', data.toString());
            });

            runningProcess.on('close', (code) => {
                socket.emit('output', `\r\n\x1B[1;36m[+] Process finished with exit code ${code}\x1B[0m\r\n`);
                socket.emit('process_exit', { code });
                runningProcess = null;
            });

            runningProcess.on('error', (err) => {
                socket.emit('output', `\r\n\x1B[1;31m[!] Process Error: ${err.message}\x1B[0m\r\n`);
                runningProcess = null;
            });

        } catch (e) {
            socket.emit('output', `\r\n\x1B[1;31m[!] Shell Execution Exception: ${e.message}\x1B[0m\r\n`);
            runningProcess = null;
        }
    });

    socket.on('stdin_input', (inputData) => {
        if (runningProcess) {
            runningProcess.stdin.write(inputData);
        }
    });

    socket.on('kill_process', () => {
        if (runningProcess) {
            socket.emit('output', '\r\n\x1B[1;33m[!] Terminating process...\x1B[0m\r\n');
            if (process.platform !== 'win32') {
                exec(`sudo kill -9 -${runningProcess.pid}`, () => {});
            }
            runningProcess.kill('SIGKILL');
            runningProcess = null;
        }
    });

    // INTERACTIVE SSH EMULATOR BRIDGE
    socket.on('ssh_connect', (data) => {
        if (sshClient || sshShell) {
            socket.emit('ssh_output', '\r\n\x1B[1;31m[!] Already connected to an active SSH session. Disconnect first.\x1B[0m\r\n');
            return;
        }

        const { host, port, username, password, privateKey } = data;
        if (!host || !username) {
            socket.emit('ssh_output', '\r\n\x1B[1;31m[!] Error: Host and Username are required.\x1B[0m\r\n');
            return;
        }

        const resolvedPort = parseInt(port) || 22;
        socket.emit('ssh_output', `\x1B[1;32m[+] Initiating SSH: ${username}@${host}:${resolvedPort}...\x1B[0m\r\n`);
        
        sshClient = new Client();
        
        sshClient.on('ready', () => {
            socket.emit('ssh_output', `\x1B[1;32m[+] SSH Handshake Successful! Allocating pseudo-TTY shell...\x1B[0m\r\n\r\n`);
            sshClient.shell({ term: 'xterm-color', cols: 80, rows: 24 }, (err, stream) => {
                if (err) {
                    socket.emit('ssh_output', `\r\n\x1B[1;31m[!] Error creating SSH shell: ${err.message}\x1B[0m\r\n`);
                    sshClient.end();
                    sshClient = null;
                    return;
                }
                sshShell = stream;
                
                stream.on('data', (data) => {
                    socket.emit('ssh_output', data.toString());
                });

                stream.on('close', () => {
                    socket.emit('ssh_output', `\r\n\x1B[1;36m[+] SSH remote shell closed.\x1B[0m\r\n`);
                    socket.emit('ssh_closed');
                    sshShell = null;
                    if (sshClient) {
                        sshClient.end();
                        sshClient = null;
                    }
                });

                socket.emit('ssh_connected');
            });
        });

        sshClient.on('error', (err) => {
            socket.emit('ssh_output', `\r\n\x1B[1;31m[!] SSH Client Error: ${err.message}\x1B[0m\r\n`);
            sshClient = null;
            sshShell = null;
            socket.emit('ssh_closed');
        });

        sshClient.on('end', () => {
            socket.emit('ssh_output', `\r\n\x1B[1;33m[!] SSH Connection terminated.\x1B[0m\r\n`);
            sshClient = null;
            sshShell = null;
            socket.emit('ssh_closed');
        });

        const connectionConfig = {
            host: host,
            port: resolvedPort,
            username: username,
            readyTimeout: 20000
        };

        if (privateKey) {
            connectionConfig.privateKey = privateKey;
        } else if (password) {
            connectionConfig.password = password;
        }

        try {
            sshClient.connect(connectionConfig);
        } catch (e) {
            socket.emit('ssh_output', `\r\n\x1B[1;31m[!] SSH Connection Exception: ${e.message}\x1B[0m\r\n`);
            sshClient = null;
            sshShell = null;
            socket.emit('ssh_closed');
        }
    });

    socket.on('ssh_input', (inputData) => {
        if (sshShell) {
            sshShell.write(inputData);
        }
    });

    socket.on('ssh_resize', (dimensions) => {
        if (sshShell && dimensions) {
            sshShell.setWindow(dimensions.rows || 24, dimensions.cols || 80, 0, 0);
        }
    });

    socket.on('ssh_disconnect', () => {
        if (sshClient) {
            socket.emit('ssh_output', '\r\n\x1B[1;33m[+] Disconnecting SSH...\x1B[0m\r\n');
            sshClient.end();
            sshClient = null;
            sshShell = null;
        }
    });

    // Cleanup on disconnect
    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
        if (runningProcess) {
            runningProcess.kill('SIGKILL');
            runningProcess = null;
        }
        if (sshClient) {
            sshClient.end();
            sshClient = null;
            sshShell = null;
        }
    });
});

server.listen(PORT, () => {
    console.log(`ANDRAX GUI server is running on http://localhost:${PORT}`);
});
