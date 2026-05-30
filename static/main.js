// Global Loading Screen helpers
function showLoadingScreen() {
    const loadingOverlay = document.getElementById('loading-overlay');
    if (loadingOverlay) {
        loadingOverlay.style.display = 'flex';
    }
}

function hideLoadingScreen() {
    const loadingOverlay = document.getElementById('loading-overlay');
    if (loadingOverlay) {
        loadingOverlay.style.display = 'none';
    }
}

// Show loading screen on form submission
document.addEventListener('DOMContentLoaded', function() {
    const forms = document.querySelectorAll('form:not(#playground-form):not(#dash-convert-form)');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            showLoadingScreen();
        });
    });
});

window.addEventListener('load', function() {
    hideLoadingScreen();
});

// Password toggles and validation
function validatePassword() {
    const password = document.getElementById("password");
    const confirmPassword = document.getElementById("confirm_password");

    if (password && confirmPassword && password.value !== confirmPassword.value) {
        alert("Passwords do not match!");
        return false;
    }
    return true;
}

function togglePasswordVisibility_all() {
    const passwordInput = document.getElementById("password");
    const confirmPasswordInput = document.getElementById("confirm_password");

    if (passwordInput) {
        passwordInput.type = passwordInput.type === "password" ? "text" : "password";
    }
    if (confirmPasswordInput) {
        confirmPasswordInput.type = confirmPasswordInput.type === "password" ? "text" : "password";
    }
}

// -----------------------------------------------------------------------------
// GUEST API KEY MANAGEMENT & INTERACTIVE PLAYGROUND
// -----------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', function() {
    // Elements on the landing page
    const onboardKeyInput = document.getElementById('onboard-api-key');
    const onboardUrlInput = document.getElementById('onboard-api-url');
    const copyKeyBtn = document.getElementById('copy-onboard-key-btn');
    const copyUrlBtn = document.getElementById('copy-onboard-url-btn');
    const refreshKeyBtn = document.getElementById('refresh-guest-key-btn');
    
    // Playground Elements
    const playKeyInput = document.getElementById('play-api-key');
    const playBaseInput = document.getElementById('play-base');
    const playTargetInput = document.getElementById('play-target');
    const playAmountInput = document.getElementById('play-amount');
    const playSendBtn = document.getElementById('play-send-btn');
    const playSendIcon = document.getElementById('play-send-icon');
    const playSendText = document.getElementById('play-send-text');
    const playResponseCode = document.getElementById('play-response-code');
    const playUrlPreview = document.getElementById('play-url-preview');
    const playStatusPill = document.getElementById('play-status-pill');
    const playTimeElapsed = document.getElementById('play-time-elapsed');
    const playCopyResponseBtn = document.getElementById('play-copy-response-btn');
    
    // Playground Endpoint Tabs
    const tabRates = document.getElementById('endpoint-tab-rates');
    const tabConvert = document.getElementById('endpoint-tab-convert');
    let currentEndpoint = 'rates'; // 'rates' or 'convert'

    // Code template database
    let activeKey = 'YOUR_API_KEY';
    
    // Initial key fetch sequence
    async function loadOrCreateGuestKey(force = false) {
        let key = localStorage.getItem('imhotep_guest_key');
        
        if (!key || force) {
            if (onboardKeyInput) onboardKeyInput.value = 'Generating key...';
            try {
                const response = await fetch('/api/get_guest_key', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                if (response.ok) {
                    const data = await response.json();
                    key = data.api_key;
                    localStorage.setItem('imhotep_guest_key', key);
                } else {
                    key = 'demo'; // Fallback to demo
                }
            } catch (err) {
                console.error('Failed to generate guest key:', err);
                key = 'demo';
            }
        }
        
        activeKey = key;
        updateUIWithKey(key);
    }

    function updateUIWithKey(key) {
        // Update onboard inputs
        if (onboardKeyInput) {
            onboardKeyInput.value = key;
            if (copyKeyBtn) copyKeyBtn.disabled = false;
        }
        if (onboardUrlInput) {
            onboardUrlInput.value = `https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/${key}/USD`;
            if (copyUrlBtn) copyUrlBtn.disabled = false;
        }

        // Update playground inputs
        if (playKeyInput) {
            playKeyInput.value = key;
        }
        
        // Refresh playground URL preview
        updatePlaygroundUrlPreview();
        updateCodeBlockTemplates(key);
    }

    function updatePlaygroundUrlPreview() {
        if (!playUrlPreview) return;
        const key = (playKeyInput ? playKeyInput.value.trim() : '') || activeKey;
        const base = (playBaseInput ? playBaseInput.value.trim().toUpperCase() : 'USD') || 'USD';
        
        if (currentEndpoint === 'rates') {
            playUrlPreview.textContent = `/latest_rates/${key}/${base}`;
        } else {
            const target = (playTargetInput ? playTargetInput.value.trim().toUpperCase() : 'EUR') || 'EUR';
            const amount = (playAmountInput ? playAmountInput.value.trim() : '100') || '100';
            playUrlPreview.textContent = `/convert/latest_rates/${key}/${base}/${target}/${amount}`;
        }
    }

    // Dynamic docs pre-filling templates
    const docsTemplates = {
        latest: {
            js: (key) => `// Fetch latest exchange rates\nconst url = 'https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/${key}/USD';\n\nfetch(url)\n  .then(res => res.json())\n  .then(data => {\n    console.log('Exchange rates:', data.data);\n  })\n  .catch(err => console.error(err));`,
            python: (key) => `import requests\n\nurl = 'https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/${key}/USD'\ntry:\n    res = requests.get(url)\n    data = res.json()\n    print(data['data'])\nexcept Exception as e:\n    print(e)`,
            curl: (key) => `curl -X GET "https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/${key}/USD"`,
            go: (key) => `package main\n\nimport (\n\t"fmt"\n\t"io/ioutil"\n\t"net/http"\n)\n\nfunc main() {\n\turl := "https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/${key}/USD"\n\tresp, _ := http.Get(url)\n\tdefer resp.Body.Close()\n\tbody, _ := ioutil.ReadAll(resp.Body)\n\tfmt.Println(string(body))\n}`
        },
        convert: {
            js: (key) => `// Convert currency amount\nconst url = 'https://imhotepexchangeratesapi.pythonanywhere.com/convert/latest_rates/${key}/USD/EUR/100';\n\nfetch(url)\n  .then(res => res.json())\n  .then(data => {\n    console.log(\`Converted: \${data.data.converted_amount}\`);\n  })\n  .catch(err => console.error(err));`,
            python: (key) => `import requests\n\nurl = 'https://imhotepexchangeratesapi.pythonanywhere.com/convert/latest_rates/${key}/USD/EUR/100'\ntry:\n    res = requests.get(url)\n    data = res.json()\n    print(data['data']['converted_amount'])\nexcept Exception as e:\n    print(e)`,
            curl: (key) => `curl -X GET "https://imhotepexchangeratesapi.pythonanywhere.com/convert/latest_rates/${key}/USD/EUR/100"`,
            go: (key) => `package main\n\nimport (\n\t"fmt"\n\t"io/ioutil"\n\t"net/http"\n)\n\nfunc main() {\n\turl := "https://imhotepexchangeratesapi.pythonanywhere.com/convert/latest_rates/${key}/USD/EUR/100"\n\tresp, _ := http.Get(url)\n\tdefer resp.Body.Close()\n\tbody, _ := ioutil.ReadAll(resp.Body)\n\tfmt.Println(string(body))\n}`
        }
    };

    function updateCodeBlockTemplates(key) {
        // Fill initial active tab templates for latest and convert
        const blockLatest = document.getElementById('code-block-latest');
        if (blockLatest) {
            blockLatest.textContent = docsTemplates.latest.js(key);
        }
        const blockConvert = document.getElementById('code-block-convert');
        if (blockConvert) {
            blockConvert.textContent = docsTemplates.convert.js(key);
        }
    }

    // Playground switcher
    if (tabRates && tabConvert) {
        tabRates.addEventListener('click', function() {
            currentEndpoint = 'rates';
            tabRates.className = 'endpoint-tab-btn py-2 text-xs font-bold rounded-lg border border-brand-500/30 bg-brand-500/10 text-white transition-all';
            tabConvert.className = 'endpoint-tab-btn py-2 text-xs font-bold rounded-lg border border-gray-800 bg-[#0B0F19] text-gray-400 hover:text-white transition-all';
            
            document.getElementById('play-target-wrapper')?.classList.add('hidden');
            document.getElementById('play-amount-wrapper')?.classList.add('hidden');
            updatePlaygroundUrlPreview();
        });

        tabConvert.addEventListener('click', function() {
            currentEndpoint = 'convert';
            tabConvert.className = 'endpoint-tab-btn py-2 text-xs font-bold rounded-lg border border-brand-500/30 bg-brand-500/10 text-white transition-all';
            tabRates.className = 'endpoint-tab-btn py-2 text-xs font-bold rounded-lg border border-gray-800 bg-[#0B0F19] text-gray-400 hover:text-white transition-all';
            
            document.getElementById('play-target-wrapper')?.classList.remove('hidden');
            document.getElementById('play-amount-wrapper')?.classList.remove('hidden');
            updatePlaygroundUrlPreview();
        });
    }

    // Playground updates on input changes
    [playKeyInput, playBaseInput, playTargetInput, playAmountInput].forEach(input => {
        input?.addEventListener('input', updatePlaygroundUrlPreview);
    });

    // Send Playground Request
    if (playSendBtn) {
        playSendBtn.addEventListener('click', async function() {
            const key = (playKeyInput ? playKeyInput.value.trim() : '') || activeKey;
            const base = (playBaseInput ? playBaseInput.value.trim().toUpperCase() : 'USD') || 'USD';
            
            let url = `/latest_rates/${encodeURIComponent(key)}/${encodeURIComponent(base)}`;
            if (currentEndpoint === 'convert') {
                const target = (playTargetInput ? playTargetInput.value.trim().toUpperCase() : 'EUR') || 'EUR';
                const amount = (playAmountInput ? playAmountInput.value.trim() : '100') || '100';
                url = `/convert/latest_rates/${encodeURIComponent(key)}/${encodeURIComponent(base)}/${encodeURIComponent(target)}/${encodeURIComponent(amount)}`;
            }

            // Set loading state
            playSendBtn.disabled = true;
            if (playSendIcon) playSendIcon.className = 'fa-solid fa-arrows-spin fa-spin mr-1.5';
            if (playSendText) playSendText.textContent = 'Sending...';
            if (playResponseCode) playResponseCode.textContent = '// Sending API request...';
            if (playStatusPill) {
                playStatusPill.className = 'inline-flex items-center gap-1';
                playStatusPill.innerHTML = '<span class="h-2 w-2 rounded-full bg-yellow-500 animate-pulse"></span> Querying';
            }

            const startTime = performance.now();

            try {
                const response = await fetch(url);
                const data = await response.json();
                const elapsed = Math.round(performance.now() - startTime);

                if (playResponseCode) playResponseCode.textContent = JSON.stringify(data, null, 2);
                if (playTimeElapsed) playTimeElapsed.textContent = `${elapsed} ms`;
                
                if (playStatusPill) {
                    if (response.ok) {
                        playStatusPill.className = 'inline-flex items-center gap-1 bg-emerald-500/10 border border-emerald-500/25 px-2 py-0.5 rounded text-emerald-400';
                        playStatusPill.innerHTML = `<span class="h-1.5 w-1.5 rounded-full bg-emerald-500"></span> ${response.status} OK`;
                    } else {
                        playStatusPill.className = 'inline-flex items-center gap-1 bg-rose-500/10 border border-rose-500/25 px-2 py-0.5 rounded text-rose-400';
                        playStatusPill.innerHTML = `<span class="h-1.5 w-1.5 rounded-full bg-rose-500"></span> ${response.status} Error`;
                    }
                }
            } catch (err) {
                console.error(err);
                if (playResponseCode) playResponseCode.textContent = JSON.stringify({ error: { code: 500, message: 'Network request failed' } }, null, 2);
                if (playStatusPill) {
                    playStatusPill.className = 'inline-flex items-center gap-1 bg-rose-500/10 border border-rose-500/25 px-2 py-0.5 rounded text-rose-400';
                    playStatusPill.innerHTML = '<span class="h-1.5 w-1.5 rounded-full bg-rose-500"></span> Failed';
                }
            } finally {
                playSendBtn.disabled = false;
                if (playSendIcon) playSendIcon.className = 'fa-solid fa-paper-plane mr-1.5';
                if (playSendText) playSendText.textContent = 'Send Request';
            }
        });
    }

    // ----------------------------------------------------
    // DOCS CODE EXAMPLE TAB SWITCHING (LANDING PAGE)
    // ----------------------------------------------------
    const codeTabBtns = document.querySelectorAll('#docs .code-tab-btn');
    codeTabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const section = this.getAttribute('data-section');
            const lang = this.getAttribute('data-lang');
            
            // Highlight button
            const siblingBtns = this.parentElement.querySelectorAll('.code-tab-btn');
            siblingBtns.forEach(sb => {
                sb.classList.remove('bg-gray-800', 'text-white');
                sb.classList.add('text-gray-400');
            });
            this.classList.add('bg-gray-800', 'text-white');
            this.classList.remove('text-gray-400');

            // Replace content
            const targetBlock = document.getElementById(`code-block-${section}`);
            if(targetBlock && docsTemplates[section] && docsTemplates[section][lang]) {
                targetBlock.textContent = docsTemplates[section][lang](activeKey);
            }
        });
    });

    // Code copy helper for docs
    const copyBlockBtns = document.querySelectorAll('#docs .copy-code-block-btn');
    copyBlockBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const codeBlock = document.getElementById(targetId);
            if(codeBlock) {
                navigator.clipboard.writeText(codeBlock.textContent).then(() => {
                    const originalHtml = this.innerHTML;
                    this.innerHTML = '<i class="fa-solid fa-check text-emerald-400"></i> Copied!';
                    setTimeout(() => {
                        this.innerHTML = originalHtml;
                    }, 2000);
                });
            }
        });
    });

    // Simple visual click-to-copy utility for onboard keys
    function setupOnboardCopy(button, input, successHtml) {
        if (!button || !input) return;
        const originalHtml = button.innerHTML;
        button.addEventListener('click', function() {
            navigator.clipboard.writeText(input.value).then(() => {
                button.innerHTML = successHtml;
                setTimeout(() => { button.innerHTML = originalHtml; }, 2000);
            });
        });
    }

    setupOnboardCopy(copyKeyBtn, onboardKeyInput, '<i class="fa-solid fa-check text-emerald-400"></i>');
    setupOnboardCopy(copyUrlBtn, onboardUrlInput, '<i class="fa-solid fa-check text-emerald-400"></i>');

    if (refreshKeyBtn) {
        refreshKeyBtn.addEventListener('click', function(e) {
            e.preventDefault();
            loadOrCreateGuestKey(true);
        });
    }

    if (playCopyResponseBtn && playResponseCode) {
        playCopyResponseBtn.addEventListener('click', function() {
            navigator.clipboard.writeText(playResponseCode.textContent).then(() => {
                const originalHtml = playCopyResponseBtn.innerHTML;
                playCopyResponseBtn.innerHTML = '<i class="fa-solid fa-check text-emerald-400"></i> Copied!';
                setTimeout(() => { playCopyResponseBtn.innerHTML = originalHtml; }, 2000);
            });
        });
    }

    // Trigger onboarding key fetch
    if (onboardKeyInput || playKeyInput) {
        loadOrCreateGuestKey();
    }
});