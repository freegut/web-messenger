class SecureChat {
    constructor() {
        this.ws = new WebSocket("ws://localhost:8765/ws");
        this.username = null;
        this.keyPair = null;
        this.publicKeys = new Map();
        this.sessionToken = localStorage.getItem("session_token");
        this.isAdmin = false;
        
        this.showLoginPrompt();
    }

    showLoginPrompt() {
        const loginDiv = document.getElementById("login");
        loginDiv.style.display = "block";
        document.getElementById("chat").style.display = "none";
        document.getElementById("admin-panel").style.display = "none";
    }

    async login() {
        this.username = document.getElementById("login-username").value.trim();
        const password = document.getElementById("login-password").value.trim();
        if (!this.username || !password) {
            alert("Please enter username and password");
            return;
        }
        
        this.ws.send(JSON.stringify({
            type: "login",
            username: this.username,
            password: password
        }));
    }

    async generateKeys() {
        this.keyPair = await window.crypto.subtle.generateKey(
            { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            true,
            ["encrypt", "decrypt"]
        );
    }

    setupListeners() {
        document.getElementById("login-btn").addEventListener("click", () => this.login());
        document.getElementById("send-btn").addEventListener("click", () => this.sendMessage());
        document.getElementById("create-conf-btn").addEventListener("click", () => this.createConference());
        document.getElementById("register-user-btn").addEventListener("click", () => this.registerUser());
        document.getElementById("change-password-btn").addEventListener("click", () => this.changePassword());
        document.getElementById("delete-user-btn").addEventListener("click", () => this.deleteUser());
        
        this.ws.onmessage = async (e) => {
            const data = JSON.parse(e.data);
            console.log("Получено:", data);
            
            if (data.type === "login_success") {
                this.sessionToken = data.session_token;
                this.isAdmin = data.is_admin;
                localStorage.setItem("session_token", this.sessionToken);
                document.getElementById("login").style.display = "none";
                document.getElementById("chat").style.display = "block";
                document.getElementById("admin-panel").style.display = this.isAdmin ? "block" : "none";
                await this.generateKeys();
            } else if (data.type === "message") {
                const decrypted = await this.decryptMessage(data.text);
                this.displayMessage(`${data.from}: ${decrypted}`);
            } else if (data.type === "user_list") {
                this.updateUserList(data.users);
            } else if (data.type === "public_key") {
                if (data.pubkey) {
                    const key = await window.crypto.subtle.importKey(
                        "jwk",
                        JSON.parse(data.pubkey),
                        { name: "RSA-OAEP", hash: "SHA-256" },
                        true,
                        ["encrypt"]
                    );
                    this.publicKeys.set(data.username, key);
                }
            } else if (data.type === "conference_update") {
                this.displayConference(data.conf_id, data.members);
            } else if (data.type === "register_success" || data.type === "change_password_success" || data.type === "delete_user_success") {
                alert(data.message);
            } else if (data.type === "error") {
                alert(data.message);
            }
        };
    }

    async registerUser() {
        const username = document.getElementById("admin-reg-username").value.trim();
        const password = document.getElementById("admin-reg-password").value.trim();
        const isAdmin = document.getElementById("admin-reg-is-admin").checked;
        if (!username || !password) {
            alert("Please enter username and password");
            return;
        }
        
        const pubKey = await window.crypto.subtle.exportKey("jwk", this.keyPair.publicKey);
        this.ws.send(JSON.stringify({
            type: "register_user",
            username: username,
            password: password,
            pubkey: JSON.stringify(pubKey),
            is_admin: isAdmin
        }));
    }

    async changePassword() {
        const username = document.getElementById("admin-change-username").value.trim();
        const password = document.getElementById("admin-change-password").value.trim();
        if (!username || !password) {
            alert("Please enter username and password");
            return;
        }
        
        this.ws.send(JSON.stringify({
            type: "change_password",
            username: username,
            password: password
        }));
    }

    async deleteUser() {
        const username = document.getElementById("admin-delete-username").value.trim();
        if (!username) {
            alert("Please enter username");
            return;
        }
        
        this.ws.send(JSON.stringify({
            type: "delete_user",
            username: username
        }));
    }

    async sendMessage() {
        const recipient = document.getElementById("recipient").value.trim();
        const input = document.getElementById("message-input");
        const message = input.value.trim();
        if (!recipient || !message) {
            alert("Please enter recipient and message");
            return;
        }
        
        input.value = "";
        
        if (!this.publicKeys.has(recipient)) {
            await this.fetchPublicKey(recipient);
        }
        
        const pubKey = this.publicKeys.get(recipient);
        if (!pubKey) {
            alert(`Recipient ${recipient} not found`);
            return;
        }
        
        const encrypted = await this.encryptMessage(message, pubKey);
        this.ws.send(JSON.stringify({
            type: "message",
            text: encrypted,
            from: this.username,
            recipient: recipient
        }));
        this.displayMessage(`You to ${recipient}: ${message}`);
    }

    async encryptMessage(message, pubKey) {
        const encoded = new TextEncoder().encode(message);
        const encrypted = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            pubKey,
            encoded
        );
        return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
    }

    async decryptMessage(encrypted) {
        const decoded = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            this.keyPair.privateKey,
            decoded
        );
        return new TextDecoder().decode(decrypted);
    }

    async fetchPublicKey(username) {
        return new Promise((resolve) => {
            this.ws.send(JSON.stringify({
                type: "get_public_key",
                username: username
            }));
            setTimeout(resolve, 1000);
        });
    }

    updateUserList(users) {
        const select = document.getElementById("recipient");
        select.innerHTML = '<option value="">Select recipient</option>' +
            users
                .filter(u => u !== this.username)
                .map(u => `<option value="${u}">${u}</option>`)
                .join("");
    }

    displayMessage(message) {
        const messages = document.getElementById("messages");
        const div = document.createElement("div");
        div.textContent = message;
        messages.appendChild(div);
        messages.scrollTop = messages.scrollHeight;
    }

    displayConference(confId, members) {
        const conferences = document.getElementById("conferences");
        const div = document.createElement("div");
        div.textContent = `Conference ${confId}: ${members.join(", ")}`;
        conferences.appendChild(div);
    }

    createConference() {
        const confId = document.getElementById("conf-id").value.trim();
        const members = document.getElementById("conf-members").value.split(",").map(m => m.trim()).filter(m => m);
        if (!confId || members.length === 0) {
            alert("Please enter conference ID and members");
            return;
        }
        this.ws.send(JSON.stringify({
            type: "create_conference",
            conf_id: confId,
            members: members
        }));
        document.getElementById("conf-id").value = "";
        document.getElementById("conf-members").value = "";
    }
}

new SecureChat();