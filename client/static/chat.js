
class SecureChat {
    constructor() {
        console.log("Initializing SecureChat");
        this.ws = new WebSocket("ws://localhost:8765/ws");
        this.ws.onopen = () => console.log("WebSocket connected");
        this.ws.onerror = (e) => console.log("WebSocket error:", e);
        this.ws.onmessage = (e) => this.handleMessage(e);
        this.username = null;
        this.keyPair = null;
        this.publicKeys = new Map();
        this.sessionToken = localStorage.getItem("session_token");
        this.isAdmin = false;
        this.conferences = new Map(); // {confId: {members: [], messages: []}}
        this.users = []; // Список всех пользователей
        this.onlineUsers = []; // Список онлайн-пользователей
        this.currentConference = null; // Текущая открытая конференция
        this.selectedMembers = new Set(); // Выбранные участники для конференции
        
        this.showLoginPrompt();
        this.setupListeners();
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
                    document.getElementById("tabs").style.display = "flex";
                    document.getElementById("create-conference").style.display = "block";
                }
                await this.generateKeys();
                this.ws.send(JSON.stringify({
                    type: "get_public_key",
                    username: this.username
                }));
                this.ws.send(JSON.stringify({
                    type: "get_all_users"
                }));
                this.showGlobalChat();
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
            case "message":
                this.displayMessage(data.from, data.text);
                break;
            case "conference_update":
                this.updateConference(data.conf_id, data.members);
                break;
            case "conference_message":
                this.displayConferenceMessage(data.conf_id, data.from, data.text);
                break;
            case "public_key":
                this.publicKeys.set(data.username, data.pubkey);
                break;
            case "register_success":
                alert(`User ${data.message}`);
                this.ws.send(JSON.stringify({
                    type: "get_all_users"
                }));
                break;
            case "change_password_success":
                alert(`Password changed: ${data.message}`);
                break;
            case "delete_user_success":
                alert(`Users deleted: ${data.message}`);
                this.ws.send(JSON.stringify({
                    type: "get_all_users"
                }));
                break;
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

    showLoginPrompt() {
        document.getElementById("login").style.display = "block";
        document.getElementById("chat").style.display = "none";
        document.getElementById("tabs").style.display = "none";
        document.getElementById("create-conference").style.display = "none";
        document.getElementById("login-username").value = "";
        document.getElementById("login-password").value = "";
    }

    setupListeners() {
        console.log("Setting up listeners");
        document.getElementById("login-btn").addEventListener("click", () => this.login());
        document.getElementById("send-btn").addEventListener("click", () => this.sendMessage());
        document.getElementById("create-conf-btn").addEventListener("click", () => this.createConference());
        document.getElementById("register-user-btn").addEventListener("click", () => this.registerUser());
        document.getElementById("change-password-btn").addEventListener("click", () => this.changePassword());
        document.getElementById("delete-selected-btn").addEventListener("click", () => this.deleteSelectedUsers());
        document.getElementById("logout-btn").addEventListener("click", () => this.logout());

        // Обработчик вкладок
        document.querySelectorAll(".tab-btn").forEach(button => {
            button.addEventListener("click", () => {
                document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));
                document.querySelectorAll(".tab-pane").forEach(pane => pane.classList.remove("active"));
                document.getElementById("global-messages").classList.remove("active");
                document.getElementById("conference-content").classList.remove("active");
                
                button.classList.add("active");
                document.getElementById(button.dataset.tab).classList.add("active");
                if (button.dataset.tab === "delete-tab") {
                    this.renderUserList();
                }
            });
        });

        // Закрытие dropdown при клике вне его
        document.addEventListener("click", (event) => {
            const dropdown = document.getElementById("member-dropdown");
            const addMembersBtn = document.getElementById("add-members-btn");
            if (!dropdown.contains(event.target) && event.target !== addMembersBtn) {
                dropdown.style.display = "none";
            }
        });
    }

    showGlobalChat() {
        document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));
        document.querySelectorAll(".tab-pane").forEach(pane => pane.classList.remove("active"));
        document.getElementById("conference-content").classList.remove("active");
        document.getElementById("global-messages").classList.add("active");
        this.currentConference = null;
    }

    logout() {
        this.username = null;
        this.sessionToken = null;
        this.isAdmin = false;
        this.conferences.clear();
        this.users = [];
        this.onlineUsers = [];
        this.currentConference = null;
        this.selectedMembers.clear();
        localStorage.removeItem("session_token");
        this.ws.close();
        this.ws = new WebSocket("ws://localhost:8765/ws");
        this.ws.onopen = () => console.log("WebSocket reconnected after logout");
        this.ws.onerror = (e) => console.log("WebSocket error:", e);
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
        console.log("Sending login message");
        this.ws.send(JSON.stringify({
            type: "login",
            username: this.username,
            password: password
        }));
    }

    async sendMessage() {
        const message = document.getElementById("message-input").value.trim();
        if (!message) {
            alert("Please enter a message");
            return;
        }

        const mentionMatch = message.match(/^@(\w+)\s+(.+)/);
        if (!mentionMatch) {
            alert("Message must start with @all or @username");
            return;
        }

        const target = mentionMatch[1];
        const content = mentionMatch[2];
        let recipients = [];

        if (target.toLowerCase() === "all") {
            recipients = this.users.filter(user => user !== this.username);
        } else {
            if (!this.users.includes(target)) {
                alert(`User ${target} not found`);
                return;
            }
            recipients = [target];
        }

        const encryptedMessages = {};
        for (const recipient of recipients) {
            const pubKey = this.publicKeys.get(recipient);
            if (!pubKey) {
                this.ws.send(JSON.stringify({
                    type: "get_public_key",
                    username: recipient
                }));
                alert(`Public key for ${recipient} not found, requesting...`);
                return;
            }
            encryptedMessages[recipient] = await this.encryptMessage(content, pubKey);
        }

        this.ws.send(JSON.stringify({
            type: "message",
            recipients: recipients,
            encrypted_messages: encryptedMessages
        }));
        this.displayMessage(`You (to ${target})`, "[Encrypted]");
        document.getElementById("message-input").value = "";
    }

    async sendConferenceMessage(confId) {
        const messageInput = document.getElementById(`conf-message-input-${confId}`);
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

    toggleMemberDropdown(event) {
        event.stopPropagation();
        const dropdown = document.getElementById("member-dropdown");
        if (dropdown.style.display === "block") {
            dropdown.style.display = "none";
            return;
        }
        dropdown.style.display = "block";
        dropdown.innerHTML = "";
        this.users.forEach(user => {
            if (user !== this.username) {
                const label = document.createElement("label");
                const checkbox = document.createElement("input");
                checkbox.type = "checkbox";
                checkbox.value = user;
                checkbox.checked = this.selectedMembers.has(user);
                checkbox.addEventListener("change", () => {
                    if (checkbox.checked) {
                        this.selectedMembers.add(user);
                    } else {
                        this.selectedMembers.delete(user);
                    }
                });
                label.appendChild(checkbox);
                label.appendChild(document.createTextNode(user));
                dropdown.appendChild(label);
            }
        });
    }

    async createConference() {
        if (!this.isAdmin) {
            alert("Only admins can create conferences");
            return;
        }
        const confId = document.getElementById("conf-id").value.trim();
        const members = Array.from(this.selectedMembers);
        if (!confId || members.length === 0) {
            alert("Please enter conference ID and select members");
            return;
        }
        console.log("Creating conference:", confId, members);
        this.ws.send(JSON.stringify({
            type: "create_conference",
            conf_id: confId,
            members: members
        }));
        document.getElementById("conf-id").value = "";
        this.selectedMembers.clear();
        document.getElementById("member-dropdown").style.display = "none";
    }

    updateConference(confId, members) {
        this.conferences.set(confId, { members, messages: this.conferences.get(confId)?.messages || [] });
        this.renderConferences();
        this.currentConference = confId;
        this.showConference(confId);
    }

    renderConferences() {
        const conferenceList = document.getElementById("conference-list");
        conferenceList.innerHTML = "";
        this.conferences.forEach((conf, confId) => {
            const confDiv = document.createElement("div");
            confDiv.className = `conference-item ${this.currentConference === confId ? "active" : ""}`;
            confDiv.textContent = confId;
            confDiv.addEventListener("click", () => {
                this.currentConference = confId;
                this.showConference(confId);
            });
            conferenceList.appendChild(confDiv);
        });
    }

    searchConferences() {
        const searchInput = document.getElementById("conf-search").value.toLowerCase();
        const conferenceList = document.getElementById("conference-list");
        conferenceList.innerHTML = "";
        this.conferences.forEach((conf, confId) => {
            if (confId.toLowerCase().includes(searchInput) || conf.members.some(member => member.toLowerCase().includes(searchInput))) {
                const confDiv = document.createElement("div");
                confDiv.className = `conference-item ${this.currentConference === confId ? "active" : ""}`;
                confDiv.textContent = confId;
                confDiv.addEventListener("click", () => {
                    this.currentConference = confId;
                    this.showConference(confId);
                });
                conferenceList.appendChild(confDiv);
            }
        });
    }

    showConference(confId) {
        document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));
        document.querySelectorAll(".tab-pane").forEach(pane => pane.classList.remove("active"));
        document.getElementById("global-messages").classList.remove("active");
        document.getElementById("conference-content").classList.add("active");
        this.renderConferences();

        const conf = this.conferences.get(confId);
        if (!conf) return;

        const confContent = document.getElementById("conference-content");
        confContent.innerHTML = `
            <h3>${confId}</h3>
            <div class="members-list" id="conf-members-${confId}"></div>
            <div class="conference-search">
                <input id="conf-search-${confId}" placeholder="Search messages...">
                <button onclick="chat.searchConferenceMessages('${confId}')"><i class="fas fa-search"></i> Search</button>
            </div>
            <div class="conference-messages" id="conf-messages-${confId}"></div>
            <div class="conference-input-container">
                <input id="conf-message-input-${confId}" placeholder="Type your message...">
                <button onclick="chat.sendConferenceMessage('${confId}')">Send</button>
            </div>
        `;
        this.renderConferenceMembers(confId, conf.members);
        this.renderConferenceMessages(confId, conf.messages);
    }

    renderConferenceMembers(confId, members) {
        const membersList = document.getElementById(`conf-members-${confId}`);
        membersList.innerHTML = "";
        members.forEach(member => {
            const memberDiv = document.createElement("div");
            memberDiv.className = "member-item";
            const isOnline = this.onlineUsers.includes(member);
            memberDiv.innerHTML = `
                <span class="online-status ${isOnline ? 'online' : 'offline'}"></span>
                ${member}
            `;
            membersList.appendChild(memberDiv);
        });
    }

    renderConferenceMessages(confId, messages) {
        const messagesDiv = document.getElementById(`conf-messages-${confId}`);
        messagesDiv.innerHTML = "";
        messages.forEach(msg => {
            const msgDiv = document.createElement("div");
            msgDiv.className = msg.from === "You" ? "sent" : "received";
            msgDiv.innerHTML = `
                ${msg.from}: [Encrypted]
                <div class="message-timestamp">${new Date(msg.timestamp).toLocaleTimeString()}</div>
            `;
            messagesDiv.appendChild(msgDiv);
        });
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }

    searchConferenceMessages(confId) {
        const searchInput = document.getElementById(`conf-search-${confId}`).value.toLowerCase();
        const conf = this.conferences.get(confId);
        if (!conf) return;
        const filteredMessages = searchInput
            ? conf.messages.filter(msg => msg.from.toLowerCase().includes(searchInput) || "[Encrypted]".includes(searchInput))
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
        this.ws.send(JSON.stringify({
            "type": "register_user",
            username: username,
            password: password,
            is_admin: isAdmin,
            pubkey: "{}"
        }));
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
        this.ws.send(JSON.stringify({
            type: "change_password",
            username: username,
            password: password
        }));
        document.getElementById("admin-change-username").value = "";
        document.getElementById("admin-change-password").value = "";
    }

    renderUserList() {
        const userList = document.getElementById("user-list");
        userList.innerHTML = "";
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
        this.ws.send(JSON.stringify({
            type: "delete_users",
            usernames: selectedUsers
        }));
    }

    updateUserList(users) {
        console.log("Updating user list:", users);
        this.onlineUsers = users;
        this.users.forEach(user => {
            if (this.conferences.size > 0 && this.currentConference) {
                this.showConference(this.currentConference);
            }
        });
    }

    displayMessage(from, text) {
        const messages = document.getElementById("messages");
        const div = document.createElement("div");
        div.className = from.startsWith("You") ? "sent" : "received";
        div.innerHTML = `
            ${from}: [Encrypted]
            <div class="message-timestamp">${new Date().toLocaleTimeString()}</div>
        `;
        messages.appendChild(div);
        messages.scrollTop = messages.scrollHeight;
    }
}

const chat = new SecureChat();