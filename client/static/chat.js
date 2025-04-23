class SecureChat {
    constructor() {
        this.ws = new WebSocket("ws://localhost:8765/ws");
        this.username = prompt("Ваш логин:");
        this.keyPair = null;
        
        this.init().catch(console.error);
    }

    async init() {
        await this.generateKeys();
        this.setupListeners();
        await this.register();
    }

    async generateKeys() {
        this.keyPair = await window.crypto.subtle.generateKey(
            { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            true,
            ["encrypt", "decrypt"]
        );
    }

    async register() {
        const pubKey = await window.crypto.subtle.exportKey("jwk", this.keyPair.publicKey);
        this.ws.send(JSON.stringify({
            type: "register",
            username: this.username,
            pubkey: JSON.stringify(pubKey)
        }));
    }

    setupListeners() {
        document.getElementById("send-btn").addEventListener("click", () => this.sendMessage());
        this.ws.onmessage = (e) => {
            const data = JSON.parse(e.data);
            console.log("Получено:", data);
        };
    }

    async sendMessage() {
        const input = document.getElementById("message-input");
        const message = input.value;
        input.value = "";
        
        // В реальном приложении здесь будет шифрование для получателя
        this.ws.send(JSON.stringify({
            type: "message",
            text: message,
            from: this.username
        }));
    }
}

new SecureChat();