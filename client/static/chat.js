class SecureChat {
    constructor() {
        console.log("Initializing SecureChat");
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectInterval = 3000;
        this.username = null;
        this.keyPair = null;
        this.publicKeys = new Map();
        this.sessionToken = localStorage.getItem("session_token");
        this.isAdmin = false;
        this.conferences = new Map();
        this.users = [];
        this.onlineUsers = [];
        this.currentConference = null;
        this.selectedMembers = new Set();
        this.lastActivity = new Map();
        this.activityTimeouts = new Map();

        this.connectWebSocket();
        this.showLoginPrompt(true);
        this.setupListeners();
        this.startActivityTracking();
    }

    connectWebSocket() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            alert("Unable to connect to the server after multiple attempts. Please check if the server is running and try again later.");
            console.error("Max reconnect attempts reached. Stopping reconnection.");
            return;
        }

        console.log("Attempting to connect WebSocket...");
        this.ws = new WebSocket("ws://localhost:8765");
        this.ws.onopen = () => {
            console.log("WebSocket connected");
            this.reconnectAttempts = 0; // Сбрасываем счётчик попыток
        };
        this.ws.onclose = () => {
            console.log("WebSocket disconnected");
            this.showLoginPrompt();
            this.reconnectAttempts++;
            setTimeout(() => this.connectWebSocket(), this.reconnectInterval);
        };
        this.ws.onerror = (e) => {
            console.log("WebSocket error:", e);
        };
        this.ws.onmessage = (e) => this.handleMessage(e);
    }

    async login() {
        this.username = document.getElementById("login-username").value.trim();
        const password = document.getElementById("login-password").value.trim();
        console.log("Login attempt:", this.username, password);
        if (!this.username || !password) {
            alert("Please enter username and password");
            return;
        }
        if (this.ws.readyState === WebSocket.OPEN) {
            console.log("Sending login message");
            this.ws.send(JSON.stringify({
                type: "login",
                username: this.username,
                password: password
            }));
        } else {
            console.log("WebSocket is not open, waiting for reconnection...");
            alert("Cannot connect to the server. Retrying...");
        }
    }

    logout() {
        this.username = null;
        this.sessionToken = null;
        this.isAdmin = false;
        this.conferences.clear();
        this.users = [];
        this.onlineUsers = [];
        this.lastActivity.clear();
        this.activityTimeouts.clear();
        this.currentConference = null;
        this.selectedMembers.clear();
        localStorage.removeItem("session_token");
        this.reconnectAttempts = 0; // Сбрасываем попытки переподключения
        this.ws.close();
        this.showLoginPrompt(true);
    }

    async handleMessage(event) {
        try {
            const data = JSON.parse(event.data);
            console.log("Received message:", data);

            switch (data.type) {
                case "login_success":
                    alert("Login successful!");
                    this.sessionToken = data.session_token;
                    localStorage.setItem("session_token", this.sessionToken);
                    this.isAdmin = data.is_admin;
                    document.getElementById("login").style.display = "none";
                    document.getElementById("chat").style.display = "flex";
                    await this.generateKeys();
                    this.ws.send(JSON.stringify({
                        type: "get_public_key",
                        username: this.username
                    }));
                    this.ws.send(JSON.stringify({
                        type: "get_all_users"
                    }));
                    this.ws.send(JSON.stringify({
                        type: "get_conferences"
                    }));
                    this.updateLastActivity(this.username);
                    break;
                case "error":
                    console.error("Server error:", data.message);
                    alert(`Error: ${data.message}`);
                    break;
                case "user_list":
                    this.updateUserList(data.users);
                    break;
                case "all_users":
                    this.users = data.users;
                    break;
                case "conference_update":
                    this.updateConference(data.conf_id, data.members);
                    break;
                case "conference_message":
                    this.displayConferenceMessage(data.conf_id, data.from, data.text);
                    this.updateLastActivity(data.from);
                    break;
                case "public_key":
                    this.publicKeys.set(data.username, data.pubkey);
                    break;
                case "conference_list":
                    console.log("Received conference list:", data.conferences);
                    Object.entries(data.conferences).forEach(([confId, members]) => {
                        this.conferences.set(confId, { members, messages: this.conferences.get(confId)?.messages || [] });
                    });
                    this.renderConferences();
                    break;
                case "conference_messages":
                    console.log("Received conference messages:", data);
                    const conf = this.conferences.get(data.conf_id);
                    if (conf) {
                        conf.messages = data.messages.map(msg => ({
                            from: msg.from,
                            text: msg.text,
                            timestamp: new Date(msg.timestamp).getTime()
                        }));
                        if (this.currentConference === data.conf_id) {
                            this.showConference(data.conf_id);
                        }
                    }
                    break;
                default:
                    console.warn("Unknown message type:", data.type);
            }
        } catch (e) {
            console.error("Error handling message:", e);
        }
    }

    async generateKeys() {
        this.keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256"
            },
            true,
            ["encrypt", "decrypt"]
        );
        const publicKey = await window.crypto.subtle.exportKey("jwk", this.keyPair.publicKey);
        this.ws.send(JSON.stringify({
            type: "get_public_key",
            username: this.username,
            pubkey: JSON.stringify(publicKey)
        }));
    }

    showLoginPrompt(forceReset = false) {
        document.getElementById("login").style.display = "block";
        document.getElementById("chat").style.display = "none";
        if (forceReset) {
            document.getElementById("login-username").value = "";
            document.getElementById("login-password").value = "";
        }
    }

    setupListeners() {
        console.log("Setting up listeners");
        document.getElementById("login-btn").addEventListener("click", () => this.login());
        document.getElementById("logout-btn").addEventListener("click", () => this.logout());
    }

    async sendConferenceMessage(confId) {
        const safeConfId = encodeURIComponent(confId);
        const messageInput = document.getElementById(`conf-message-input-${safeConfId}`);
        const message = messageInput.value.trim();
        if (!message) {
            alert("Please enter a message");
            return;
        }
        const conf = this.conferences.get(confId);
        if (!conf) {
            alert("Conference not found");
            return;
        }
        const encryptedMessages = {};
        for (const member of conf.members) {
            if (member === this.username) continue;
            const pubKey = this.publicKeys.get(member);
            if (!pubKey) {
                this.ws.send(JSON.stringify({
                    type: "get_public_key",
                    username: member
                }));
                alert(`Public key for ${member} not found, requesting...`);
                return;
            }
            encryptedMessages[member] = await this.encryptMessage(message, pubKey);
        }
        this.ws.send(JSON.stringify({
            type: "conference_message",
            conf_id: confId,
            encrypted_messages: encryptedMessages
        }));
        this.displayConferenceMessage(confId, "You", "[Encrypted]");
        messageInput.value = "";
    }

    async encryptMessage(message, pubKeyJwk) {
        const publicKey = await window.crypto.subtle.importKey(
            "jwk",
            JSON.parse(pubKeyJwk),
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["encrypt"]
        );
        const encoded = new TextEncoder().encode(message);
        const encrypted = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            publicKey,
            encoded
        );
        return Array.from(new Uint8Array(encrypted)).map(b => b.toString(16).padStart(2, "0")).join("");
    }

    updateConference(confId, members) {
        console.log("Updating conference:", confId, members);
        this.conferences.set(confId, { members, messages: this.conferences.get(confId)?.messages || [] });
        console.log("Updated conferences map:", this.conferences);
        this.renderConferences();
        if (!this.currentConference) {
            this.currentConference = confId;
            this.showConference(confId);
        }
    }

    renderConferences() {
        const conferenceList = document.getElementById("conference-list");
        conferenceList.innerHTML = "";
        this.conferences.forEach((conf, confId) => {
            const confDiv = document.createElement("button");
            confDiv.className = `conference-item ${this.currentConference === confId ? "active" : ""}`;
            confDiv.textContent = confId;
            confDiv.addEventListener("click", () => {
                console.log("Conference clicked:", confId);
                this.currentConference = confId;
                this.showConference(confId);
            });
            conferenceList.appendChild(confDiv);
        });
    }

    showConference(confId) {
        console.log("Showing conference:", confId);
        console.log("Conferences map:", this.conferences);

        const conf = this.conferences.get(confId);
        console.log("Conference data:", conf);
        if (!conf) {
            console.error("Conference not found for ID:", confId);
            document.getElementById("conference-content").innerHTML = "<p>Conference not found.</p>";
            return;
        }

        const safeConfId = encodeURIComponent(confId);
        const confContent = document.getElementById("conference-content");
        confContent.innerHTML = `
            <div class="conference-messages" id="conf-messages-${safeConfId}"></div>
            <div class="conference-input-container">
                <input id="conf-message-input-${safeConfId}" placeholder="Type your message...">
                <button onclick="chat.sendConferenceMessage('${confId}')">Send</button>
            </div>
        `;
        confContent.classList.add("active");
        console.log("Conference content HTML set:", confContent.innerHTML);

        console.log("Rendering messages for:", confId, conf.messages);
        this.renderConferenceMessages(confId, conf.messages);

        this.ws.send(JSON.stringify({
            type: "get_conference_messages",
            conf_id: confId
        }));
    }

    renderConferenceMessages(confId, messages) {
        const safeConfId = encodeURIComponent(confId);
        const messagesDiv = document.getElementById(`conf-messages-${safeConfId}`);
        if (!messagesDiv) {
            console.error("Messages div not found for conference:", confId);
            return;
        }
        messagesDiv.innerHTML = "";
        (messages || []).forEach(msg => {
            const msgDiv = document.createElement("div");
            msgDiv.className = msg.from === "You" ? "sent" : "received";
            msgDiv.innerHTML = `
                ${msg.from}: ${msg.text}
                <div class="message-timestamp">${new Date(msg.timestamp).toLocaleTimeString()}</div>
            `;
            messagesDiv.appendChild(msgDiv);
        });
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
        console.log("Messages div HTML:", messagesDiv.innerHTML);
    }

    displayConferenceMessage(confId, from, text) {
        const conf = this.conferences.get(confId);
        if (!conf) return;
        conf.messages.push({ from, text, timestamp: Date.now() });
        if (this.currentConference === confId) {
            this.showConference(confId);
        }
    }

    getUserStatus(user) {
        if (!this.onlineUsers.includes(user)) return "offline";
        const lastActive = this.lastActivity.get(user) || 0;
        const inactiveTime = Date.now() - lastActive;
        if (inactiveTime < 5 * 60 * 1000) return "online";
        if (inactiveTime < 20 * 60 * 1000) return "inactive";
        return "offline";
    }

    updateLastActivity(user) {
        this.lastActivity.set(user, Date.now());

        if (this.activityTimeouts.has(user)) {
            clearTimeout(this.activityTimeouts.get(user));
        }

        const inactiveTimeout = setTimeout(() => {
            if (this.currentConference) {
                this.showConference(this.currentConference);
            }
        }, 5 * 60 * 1000);

        const offlineTimeout = setTimeout(() => {
            if (this.currentConference) {
                this.showConference(this.currentConference);
            }
        }, 20 * 60 * 1000);

        this.activityTimeouts.set(user, inactiveTimeout);
        this.activityTimeouts.set(user + "-offline", offlineTimeout);
    }

    startActivityTracking() {
        setInterval(() => {
            this.onlineUsers.forEach(user => {
                if (this.currentConference) {
                    this.showConference(this.currentConference);
                }
            });
        }, 60 * 1000);
    }

    updateUserList(users) {
        console.log("Updating user list:", users);
        this.onlineUsers = users;
        this.users.forEach(user => {
            if (!this.lastActivity.has(user) && users.includes(user)) {
                this.updateLastActivity(user);
            }
        });
        if (this.currentConference) {
            this.showConference(this.currentConference);
        }
    }
}

const chat = new SecureChat();