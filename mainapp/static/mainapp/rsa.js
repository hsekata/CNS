document.addEventListener('DOMContentLoaded', () => {
    const rsaInterface = {
        init() {
            // Initialize RSA components
            document.getElementById('generate-rsa-keys').addEventListener('click', () => this.generateKeys());
            document.querySelectorAll('.copy-btn').forEach(btn => {
                btn.addEventListener('click', (e) => this.handleCopy(e));
            });
            document.getElementById('rsa-encrypt-btn').addEventListener('click', () => this.handleOperation('encrypt'));
            document.getElementById('rsa-decrypt-btn').addEventListener('click', () => this.handleOperation('decrypt'));
            
            // Load keys from session if available
            const storedKeys = sessionStorage.getItem('rsaKeys');
            if (storedKeys) {
                const { publicKey, privateKey } = JSON.parse(storedKeys);
                document.getElementById('rsa-public-key').value = publicKey;
                document.getElementById('rsa-private-key').value = privateKey;
            }
        },

        async generateKeys() {
            const generateBtn = document.getElementById('generate-rsa-keys');
            try {
                generateBtn.disabled = true;
                generateBtn.textContent = 'Generating...';
                
                const response = await fetch('/api/generate-rsa-keys', {
                    method: 'POST',
                    headers: {
                        'X-CSRFToken': getCSRFToken(),
                        'Content-Type': 'application/json'
                    }
                });

                if (!response.ok) throw new Error('Key generation failed');
                
                const { publicKey, privateKey } = await response.json();
                this.updateKeyDisplays(publicKey, privateKey);
                sessionStorage.setItem('rsaKeys', JSON.stringify({ publicKey, privateKey }));
                
            } catch (error) {
                alert('Key generation failed. Please try again.');
                console.error('Error:', error);
            } finally {
                generateBtn.disabled = false;
                generateBtn.textContent = 'Generate New Keys';
            }
        },

        updateKeyDisplays(publicKey, privateKey) {
            document.getElementById('rsa-public-key').value = publicKey;
            document.getElementById('rsa-private-key').value = privateKey;
        },

        handleCopy(event) {
            const targetId = event.target.dataset.target;
            const textarea = document.getElementById(targetId);
            textarea.select();
            document.execCommand('copy');
            
            // Visual feedback
            event.target.textContent = 'Copied!';
            setTimeout(() => event.target.textContent = 'Copy', 2000);
        },

        async handleOperation(operation) {
            const inputText = document.getElementById('grid-1').value.trim();
            const outputField = document.getElementById('grid-2');
            
            if (!inputText) {
                alert('Please enter text to process');
                return;
            }

            try {
                const payload = this.createPayload(operation, inputText);
                const response = await fetch(`/api/rsa-${operation}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCSRFToken()
                    },
                    body: JSON.stringify(payload)
                });

                const data = await response.json();
                outputField.textContent = data.result || data.error || data.message;
                
            } catch (error) {
                console.error(`${operation} error:`, error);
                outputField.textContent = `Error: ${error.message}`;
            }
        },

        createPayload(operation, inputText) {
            const payload = {
                text: inputText,
                operation: operation
            };

            if (operation === 'encrypt') {
                payload.privateKey = document.getElementById('rsa-private-key').value;
            } else {
                payload.publicKey = document.getElementById('rsa-public-key').value;
            }

            if (!payload.privateKey && !payload.publicKey) {
                throw new Error('Required keys not found');
            }

            return payload;
        }
    };

    rsaInterface.init();
});