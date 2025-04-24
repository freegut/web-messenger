class SecureChat {
    constructor() {
        console.log("Initializing SecureChat");
        this.ws = new WebSocket("ws://localhost:8765/ws");
        this.ws.onopen = () => console.log("WebSocket connected");
        this.ws.onerror = (e) => console.error("WebSocket error:", e);
        this.ws.onmessage = (e) => this.handleMessage(e);
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

        this.showLoginPrompt();
        this.setupListeners();
        this.startActivityTracking();
    }

    async handleMessage(event) {
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
                document.getElementById("user-nick").textContent = this.username;
                if (this.isAdmin) {
                    console.log("User is admin, showing admin features");
                    document.getElementById("tabs").style.display = "flex";
                    document.getElementById("create-conf-btn-modal").style.display = "block";
                    document.querySelectorAll(".tab-btn[data-tab='register-tab'], .tab-btn[data-tab='change-password-tab'], .tab-btn[data-tab='delete-tab']").forEach(btn => {
                        btn.style.display = "block";
                    });
                }
                await this.generateKeys();
                this.sendIfConnected({
                    type: "get_public_key",
                    username: this.username
                });
                this.sendIfConnected({
                    type: "get_all_users"
                });
                this.sendIfConnected({
                    type: "get_conferences"
                });
                console.log("Activating Conferences tab after login");
                document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));
                document.querySelectorAll(".tab-pane").forEach(pane => {
                    pane.classList.remove("active");
                    pane.style.display = "none";
                });
                document.getElementById("conf-tab").classList.add("active");
                document.getElementById("conf-tab").style.display = "flex";
                document.querySelector(".tab-btn[data-tab='conf-tab']").classList.add("active");
                this.updateLastActivity(this.username);
                break;
            case "error":
                alert(`Error: ${data.message}`);
                break;
            case "user_list":
                this.updateUserList(data.users);
                break;
            case "all_users":
                this.users = data.users;
                this.renderUserList();
                break;
            case "conference_update":
                this.updateConference(data.conf_id, data.members);
                break;
            case "conference_message":
                if (data.encrypted_messages && data.encrypted_messages[this.username]) {
                    const encryptedMessage = data.encrypted_messages[this.username];
                    try {
                        const decryptedText = await this.decryptMessage(encryptedMessage);
                        this.displayConferenceMessage(data.conf_id, data.from, decryptedText);
                    } catch (error) {
                        console.error("Failed to decrypt message:", error);
                        this.displayConferenceMessage(data.conf_id, data.from, "[Decryption Failed]");
                    }
                } else {
                    this.displayConferenceMessage(data.conf_id, data.from, data.text);
                }
                this.updateLastActivity(data.from);
                break;
            case "public_key":
                this.publicKeys.set(data.username, data.pubkey);
                break;
            case "register_success":
                alert(`User ${data.message}`);
                this.sendIfConnected({
                    type: "get_all_users"
                });
                break;
            case "change_password_success":
                alert(`Password changed: ${data.message}`);
                break;
            case "delete_user_success":
                alert(`Users deleted: ${data.message}`);
                this.sendIfConnected({
                    type: "get_all_users"
                });
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
                    conf.messages = [];
                    for (const msg of data.messages) {
                        let text = msg.text;
                        if (msg.encrypted_messages && msg.encrypted_messages[this.username]) {
                            try {
                                text = await this.decryptMessage(msg.encrypted_messages[this.username]);
                            } catch (error) {
                                console.error("Failed to decrypt message:", error);
                                text = "[Decryption Failed]";
                            }
                        }
                        conf.messages.push({
                            from: msg.from,
                            text: text,
                            timestamp: new Date(msg.timestamp).getTime()
                        });
                    }
                    if (this.currentConference === data.conf_id) {
                        this.showConference(data.conf_id);
                    }
                }
                break;
            default:
                console.warn("Unknown message type received:", data.type);
                break;
        }
    }

    sendIfConnected(message) {
        if (this.ws.readyState === WebSocket.OPEN) {
            console.log("Sending message:", message);
            this.ws.send(JSON.stringify(message));
        } else {
            console.error("WebSocket is not connected. Current state:", this.ws.readyState);
            alert("Connection to server lost. Please try logging in again.");
            this.logout();
        }
    }

    async generateKeys() {
        console.log("Generating RSA key pair for", this.username);
        try {
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
            this.sendIfConnected({
                type: "get_public_key",
                username: this.username,
                pubkey: JSON.stringify(publicKey)
            });
        } catch (error) {
            console.error("Failed to generate RSA keys:", error);
            alert("Failed to generate encryption keys. Please try again.");
        }
    }

    async decryptMessage(encryptedHex) {
        try {
            const encryptedBytes = new Uint8Array(
                encryptedHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
            );
            const decrypted = await window.crypto.subtle.decrypt(
                { name: "RSA-OAEP" },
                this.keyPair.privateKey,
                encryptedBytes
            );
            return new TextDecoder().decode(decrypted);
        } catch (error) {
            console.error("Decryption failed:", error);
            throw error;
        }
    }

    showLoginPrompt() {
        console.log("Showing login prompt");
        document.getElementById("login").style.display = "block";
        document.getElementById("chat").style.display = "none";
        document.getElementById("tabs").style.display = "none";
        document.getElementById("create-conf-btn-modal").style.display = "none";
        document.getElementById("login-username").value = "";
        document.getElementById("login-password").value = "";
    }

    setupListeners() {
        console.log("Setting up listeners");
        document.getElementById("login-btn").addEventListener("click", () => this.login());
        document.getElementById("register-user-btn").addEventListener("click", () => this.registerUser());
        document.getElementById("change-password-btn").addEventListener("click", () => this.changePassword());
        document.getElementById("delete-selected-btn").addEventListener("click", () => this.deleteSelectedUsers());
        document.getElementById("logout-btn").addEventListener("click", () => this.logout());
        document.getElementById("create-conf-btn-modal").addEventListener("click", () => this.showCreateConferenceModal());

        document.querySelectorAll(".tab-btn").forEach(button => {
            button.addEventListener("click", () => {
                console.log("Tab clicked:", button.dataset.tab);
                document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));
                document.querySelectorAll(".tab-pane").forEach(pane => {
                    pane.classList.remove("active");
                    pane.style.display = "none";
                    if (pane.id === "conf-tab") {
                        const confContent = document.getElementById("conference-content");
                        if (confContent) confContent.innerHTML = "";
                    } else if (pane.id === "delete-tab") {
                        const userList = document.getElementById("user-list");
                        if (userList) userList.innerHTML = "";
                    }
                });

                button.classList.add("active");
                const tabPane = document.getElementById(button.dataset.tab);
                if (tabPane) {
                    tabPane.classList.add("active");
                    tabPane.style.display = "flex";
                } else {
                    console.error("Tab pane not found for ID:", button.dataset.tab);
                }
                if (button.dataset.tab === "delete-tab") {
                    this.renderUserList();
                } else if (button.dataset.tab === "conf-tab" && this.currentConference) {
                    this.showConference(this.currentConference);
                }
            });
        });
    }

    logout() {
        console.log("Logging out user:", this.username);
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
        this.publicKeys.clear();
        localStorage.removeItem("session_token");
        if (this.ws.readyState === WebSocket.OPEN) {
            this.ws.close();
        }
        this.ws = new WebSocket("ws://localhost:8765/ws");
        this.ws.onopen = () => console.log("WebSocket reconnected after logout");
        this.ws.onerror = (e) => console.error("WebSocket error after logout:", e);
        this.ws.onmessage = (e) => this.handleMessage(e);
        this.showLoginPrompt();
    }

    async login() {
        this.username = document.getElementById("login-username").value.trim();
        const password = document.getElementById("login-password").value.trim();
        console.log("Login attempt:", this.username, password);
        if (!this.username || !password) {
            alert("Please enter username and password");
            return;
        }
        this.sendIfConnected({
            type: "login",
            username: this.username,
            password: password
        });
    }

    async sendConferenceMessage(confId) {
        console.log("Attempting to send message in conference:", confId);
        const safeConfId = encodeURIComponent(confId);
        const messageInput = document.getElementById(`conf-message-input-${safeConfId}`);
        if (!messageInput) {
            console.error("Message input not found for conference:", confId);
            alert("Error: Message input not found");
            return;
        }
        const message = messageInput.value.trim();
        console.log("Message input value:", message);
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
                this.sendIfConnected({
                    type: "get_public_key",
                    username: member
                });
                alert(`Public key for ${member} not found, requesting...`);
                return;
            }
            try {
                encryptedMessages[member] = await this.encryptMessage(message, pubKey);
                console.log(`Encrypted message for ${member}:`, encryptedMessages[member]);
            } catch (error) {
                console.error(`Failed to encrypt message for ${member}:`, error);
                alert(`Failed to encrypt message for ${member}. Please try again.`);
                return;
            }
        }
        console.log("Sending conference message for:", confId);
        this.sendIfConnected({
            type: "conference_message",
            conf_id: confId,
            encrypted_messages: encryptedMessages
        });
        this.displayConferenceMessage(confId, "You", message);
        messageInput.value = "";
    }

    async encryptMessage(message, pubKeyJwk) {
        try {
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
        } catch (error) {
            console.error("Encryption failed:", error);
            throw error;
        }
    }

    showCreateConferenceModal() {
        this.selectedMembers.clear();
        document.getElementById("new-conf-id").value = "";
        const modal = document.getElementById("create-conference-modal");
        modal.style.display = "flex";
        this.renderNewConferenceMembersList();
    }

    showAddMembersModal() {
        this.selectedMembers.clear();
        const modal = document.getElementById("add-members-modal");
        modal.style.display = "flex";
        this.renderAddMembersList();
    }

    closeModal(modalId) {
        document.getElementById(modalId).style.display = "none";
        this.selectedMembers.clear();
    }

    renderNewConferenceMembersList() {
        const membersList = document.getElementById("new-conf-members-list");
        if (!membersList) {
            console.error("New conference members list element not found");
            return;
        }
        membersList.innerHTML = "";
        console.log("Rendering new conference members list, users:", this.users);
        if (this.users.length === 0 || this.users.length === 1) {
            membersList.innerHTML = "<p>No other users available.</p>";
            return;
        }
        this.users.forEach(user => {
            if (user !== this.username) {
                console.log("Adding user to new conference members list:", user);
                const memberDiv = document.createElement("div");
                memberDiv.className = "member-item";
                memberDiv.innerHTML = `
                    <input type="checkbox" id="new-member-${user}" value="${user}">
                    <label for="new-member-${user}">${user}</label>
                `;
                memberDiv.querySelector("input").addEventListener("change", (e) => {
                    if (e.target.checked) {
                        this.selectedMembers.add(user);
                    } else {
                        this.selectedMembers.delete(user);
                    }
                });
                membersList.appendChild(memberDiv);
            }
        });
    }

    renderAddMembersList() {
        const membersList = document.getElementById("add-members-list");
        if (!membersList) {
            console.error("Add members list element not found");
            return;
        }
        membersList.innerHTML = "";
        const conf = this.conferences.get(this.currentConference);
        if (!conf) {
            membersList.innerHTML = "<p>Conference not found.</p>";
            return;
        }
        console.log("Rendering add members list, users:", this.users, "current members:", conf.members);
        const availableUsers = this.users.filter(user => user !== this.username && !conf.members.includes(user));
        if (availableUsers.length === 0) {
            membersList.innerHTML = "<p>No users available to add.</p>";
            return;
        }
        availableUsers.forEach(user => {
            console.log("Adding user to add members list:", user);
            const memberDiv = document.createElement("div");
            memberDiv.className = "member-item";
            memberDiv.innerHTML = `
                <input type="checkbox" id="add-member-${user}" value="${user}">
                <label for="add-member-${user}">${user}</label>
            `;
            memberDiv.querySelector("input").addEventListener("change", (e) => {
                if (e.target.checked) {
                    this.selectedMembers.add(user);
                } else {
                    this.selectedMembers.delete(user);
                }
            });
            membersList.appendChild(memberDiv);
        });
    }

    async createConference() {
        if (!this.isAdmin) {
            alert("Only admins can create conferences");
            return;
        }
        const confId = document.getElementById("new-conf-id").value.trim();
        const members = Array.from(this.selectedMembers);
        members.push(this.username);
        if (!confId || members.length <= 1) {
            alert("Please enter conference ID and select at least one member");
            return;
        }
        console.log("Creating conference:", confId, members);
        this.sendIfConnected({
            type: "create_conference",
            conf_id: confId,
            members: members
        });
        this.closeModal("create-conference-modal");
    }

    async addMembersToConference() {
        if (!this.isAdmin) {
            alert("Only admins can add members to conferences");
            return;
        }
        const confId = this.currentConference;
        const conf = this.conferences.get(confId);
        const newMembers = Array.from(this.selectedMembers);
        if (newMembers.length === 0) {
            alert("Please select members to add");
            return;
        }
        const updatedMembers = [...new Set([...conf.members, ...newMembers])];
        console.log("Adding members to conference:", confId, newMembers);
        this.sendIfConnected({
            type: "create_conference",
            conf_id: confId,
            members: updatedMembers
        });
        this.closeModal("add-members-modal");
    }

    updateConference(confId, members) {
        console.log("Updating conference:", confId, members);
        this.conferences.set(confId, { members, messages: this.conferences.get(confId)?.messages || [] });
        console.log("Updated conferences map:", this.conferences);
        this.renderConferences();
        this.currentConference = confId;
        this.showConference(confId);
    }

    renderConferences() {
        const conferenceList = document.getElementById("conference-list");
        if (!conferenceList) {
            console.error("Conference list element not found");
            return;
        }
        conferenceList.innerHTML = "";
        if (this.conferences.size === 0) {
            conferenceList.innerHTML = "<p>No conferences available.</p>";
            return;
        }
        this.conferences.forEach((conf, confId) => {
            const confDiv = document.createElement("div");
            confDiv.className = `conference-item ${this.currentConference === confId ? "active" : ""}`;
            confDiv.textContent = confId;
            confDiv.addEventListener("click", () => {
                console.log("Conference clicked:", confId);
                this.showConference(confId);
            });
            conferenceList.appendChild(confDiv);
        });
    }

    searchConferences() {
        const searchInput = document.getElementById("conf-search");
        if (!searchInput) {
            console.error("Conference search input not found");
            return;
        }
        const searchValue = searchInput.value.toLowerCase();
        const conferenceList = document.getElementById("conference-list");
        if (!conferenceList) {
            console.error("Conference list element not found");
            return;
        }
        conferenceList.innerHTML = "";
        if (this.conferences.size === 0) {
            conferenceList.innerHTML = "<p>No conferences available.</p>";
            return;
        }
        let hasMatches = false;
        this.conferences.forEach((conf, confId) => {
            if (confId.toLowerCase().includes(searchValue) || conf.members.some(member => member.toLowerCase().includes(searchValue))) {
                hasMatches = true;
                const confDiv = document.createElement("div");
                confDiv.className = `conference-item ${this.currentConference === confId ? "active" : ""}`;
                confDiv.textContent = confId;
                confDiv.addEventListener("click", () => {
                    console.log("Conference clicked:", confId);
                    this.showConference(confId);
                });
                conferenceList.appendChild(confDiv);
            }
        });
        if (!hasMatches) {
            conferenceList.innerHTML = "<p>No matching conferences found.</p>";
        }
    }

    showConference(confId) {
        console.log("Showing conference:", confId);
        console.log("Conferences map:", this.conferences);

        const confTab = document.getElementById("conf-tab");
        if (!confTab.classList.contains("active")) {
            console.log("Not on Conferences tab, skipping conference rendering");
            this.currentConference = confId;
            return;
        }

        if (this.currentConference === confId) {
            const conf = this.conferences.get(confId);
            if (conf) {
                const safeConfId = encodeURIComponent(confId);
                console.log("Rendering members for:", confId, conf.members);
                this.renderConferenceMembers(confId, conf.members);
                console.log("Rendering messages for:", confId, conf.messages);
                this.renderConferenceMessages(confId, conf.messages);
            }
            return;
        }

        this.currentConference = confId;

        const conferenceList = document.getElementById("conference-list");
        if (conferenceList) {
            const confItems = conferenceList.querySelectorAll(".conference-item");
            confItems.forEach(item => {
                if (item.textContent === confId) {
                    item.classList.add("active");
                } else {
                    item.classList.remove("active");
                }
            });
        }

        const conf = this.conferences.get(confId);
        console.log("Conference data:", conf);
        if (!conf) {
            console.error("Conference not found for ID:", confId);
            const confContent = document.getElementById("conference-content");
            if (confContent) {
                confContent.innerHTML = "<p>Conference not found.</p>";
            }
            return;
        }

        const safeConfId = encodeURIComponent(confId);
        const confContent = document.getElementById("conference-content");
        if (!confContent) {
            console.error("Conference content element not found");
            return;
        }
        confContent.innerHTML = `
            <h3>${confId}</h3>
            <button onclick="chat.showAddMembersModal()" style="${this.isAdmin ? '' : 'display: none;'}">Add Members</button>
            <div class="members-list" id="conf-members-${safeConfId}"></div>
            <div class="conference-search">
                <input id="conf-search-${safeConfId}" placeholder="Search messages...">
                <button onclick="chat.searchConferenceMessages('${confId}')"><i class="fas fa-search"></i> Search</button>
            </div>
            <div class="conference-messages" id="conf-messages-${safeConfId}"></div>
            <div class="conference-input-container">
                <input id="conf-message-input-${safeConfId}" placeholder="Type your message..." autocomplete="off">
                <button onclick="chat.sendConferenceMessage('${confId}')">Send</button>
            </div>
        `;
        console.log("Conference content HTML set:", confContent.innerHTML);

        const messageInput = document.getElementById(`conf-message-input-${safeConfId}`);
        if (messageInput) {
            messageInput.removeAttribute("disabled");
            messageInput.focus();
            messageInput.addEventListener("input", (e) => {
                console.log("Input detected in message field:", e.target.value);
            });
            messageInput.addEventListener("keydown", (e) => {
                console.log("Keydown detected in message field:", e.key);
            });
            messageInput.addEventListener("click", () => {
                console.log("Message input clicked");
            });
        }

        console.log("Rendering members for:", confId, conf.members);
        this.renderConferenceMembers(confId, conf.members);
        console.log("Rendering messages for:", confId, conf.messages);
        this.renderConferenceMessages(confId, conf.messages);

        this.sendIfConnected({
            type: "get_conference_messages",
            conf_id: confId
        });
    }

    renderConferenceMembers(confId, members) {
        const safeConfId = encodeURIComponent(confId);
        const membersList = document.getElementById(`conf-members-${safeConfId}`);
        if (!membersList) {
            console.error("Members list element not found for conference:", confId);
            return;
        }
        membersList.innerHTML = "";
        members.forEach(member => {
            const memberDiv = document.createElement("div");
            memberDiv.className = "member-item";
            const status = this.getUserStatus(member);
            memberDiv.innerHTML = `
                <span class="online-status ${status}"></span>
                ${member}
            `;
            membersList.appendChild(memberDiv);
        });
        console.log("Members list HTML:", membersList.innerHTML);
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
        if (this.activityTimeouts.has(user + "-offline")) {
            clearTimeout(this.activityTimeouts.get(user + "-offline"));
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
            if (this.currentConference) {
                this.showConference(this.currentConference);
            }
        }, 60 * 1000);
    }

    renderConferenceMessages(confId, messages) {
        const safeConfId = encodeURIComponent(confId);
        const messagesDiv = document.getElementById(`conf-messages-${safeConfId}`);
        if (!messagesDiv) {
            console.error("Messages div not found for conference:", confId);
            return;
        }
        messagesDiv.innerHTML = "";
        if (messages && messages.length > 0) {
            messages.forEach(msg => {
                const msgDiv = document.createElement("div");
                msgDiv.className = msg.from === "You" ? "sent" : "received";
                msgDiv.innerHTML = `
                    ${msg.from}: ${msg.text}
                    <div class="message-timestamp">${new Date(msg.timestamp).toLocaleTimeString()}</div>
                `;
                messagesDiv.appendChild(msgDiv);
            });
        } else {
            messagesDiv.innerHTML = "<p>No messages yet.</p>";
        }
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
        console.log("Messages div HTML:", messagesDiv.innerHTML);
    }

    searchConferenceMessages(confId) {
        const safeConfId = encodeURIComponent(confId);
        const searchInput = document.getElementById(`conf-search-${safeConfId}`);
        if (!searchInput) {
            console.error("Message search input not found for conference:", confId);
            return;
        }
        const searchValue = searchInput.value.toLowerCase();
        const conf = this.conferences.get(confId);
        if (!conf) return;
        const filteredMessages = searchValue
            ? conf.messages.filter(msg => msg.from.toLowerCase().includes(searchValue) || msg.text.toLowerCase().includes(searchValue))
            : conf.messages;
        this.renderConferenceMessages(confId, filteredMessages);
    }

    displayConferenceMessage(confId, from, text) {
        const conf = this.conferences.get(confId);
        if (!conf) return;
        conf.messages.push({ from, text, timestamp: Date.now() });
        if (this.currentConference === confId) {
            this.showConference(confId);
        }
    }

    async registerUser() {
        const username = document.getElementById("admin-reg-username").value.trim();
        const password = document.getElementById("admin-reg-password").value.trim();
        const isAdmin = document.getElementById("admin-reg-is-admin").checked;
        if (!username || !password) {
            alert("Please enter username and password");
            return;
        }
        console.log("Registering user:", username, "Is Admin:", isAdmin);
        this.sendIfConnected({
            type: "register_user",
            username: username,
            password: password,
            is_admin: isAdmin,
            pubkey: "{}"
        });
        document.getElementById("admin-reg-username").value = "";
        document.getElementById("admin-reg-password").value = "";
        document.getElementById("admin-reg-is-admin").checked = false;
    }

    async changePassword() {
        const username = document.getElementById("admin-change-username").value.trim();
        const password = document.getElementById("admin-change-password").value.trim();
        if (!username || !password) {
            alert("Please enter username and new password");
            return;
        }
        console.log("Changing password for user:", username);
        this.sendIfConnected({
            type: "change_password",
            username: username,
            password: password
        });
        document.getElementById("admin-change-username").value = "";
        document.getElementById("admin-change-password").value = "";
    }

    renderUserList() {
        const userList = document.getElementById("user-list");
        if (!userList) {
            console.error("User list element not found");
            return;
        }
        userList.innerHTML = "";
        if (this.users.length === 0 || this.users.length === 1) {
            userList.innerHTML = "<p>No users available to delete.</p>";
            return;
        }
        this.users.forEach(user => {
            if (user !== this.username) {
                const userDiv = document.createElement("div");
                userDiv.className = "user-item";
                userDiv.innerHTML = `
                    <input type="checkbox" id="user-${user}" value="${user}">
                    <label for="user-${user}">${user}</label>
                `;
                userList.appendChild(userDiv);
            }
        });
    }

    async deleteSelectedUsers() {
        const selectedUsers = Array.from(document.querySelectorAll('#user-list input[type="checkbox"]:checked'))
            .map(checkbox => checkbox.value);
        if (selectedUsers.length === 0) {
            alert("Please select at least one user to delete");
            return;
        }
        console.log("Deleting users:", selectedUsers);
        this.sendIfConnected({
            type: "delete_users",
            usernames: selectedUsers
        });
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