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
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            showLoadingScreen();
        });
    });
});

// Handle page load and unload
window.addEventListener('load', function() {
    hideLoadingScreen(); // Ensure loading screen is hidden after initial load
});

window.addEventListener('beforeunload', function() {
    showLoadingScreen(); // Show loading screen when navigating away
});

// Show loading screen when navigating back
window.addEventListener('pageshow', function(event) {
    if (event.persisted) {
        showLoadingScreen();
        setTimeout(function() {
            hideLoadingScreen();
        }, 100); // Adjust delay if necessary
    }
});

window.addEventListener('online', updateOnlineStatus);
window.addEventListener('offline', updateOnlineStatus);

function updateOnlineStatus() {
    if (!navigator.onLine) {
        document.body.innerHTML = '<h1>You are offline</h1><p>Database connection is unavailable. Please check your internet connection.</p>';
    } else {
        location.reload();  // Reload when back online
    }
}

function updatePage() {
    const page = document.getElementById("page-selector");
    if (page) {
        window.location.href = `${page.value}`;
    }
}

setTimeout(function() {
    const doneMessage = document.querySelector('.done-message');
    const errorMessage = document.querySelector('.error-message');

    if (doneMessage) {
        doneMessage.style.display = 'none';
    }

    if (errorMessage) {
        errorMessage.style.display = 'none';
    }
}, 5000); // 5000 milliseconds = 5 seconds

function submitForm() {
    const uploadForm = document.getElementById("upload-form");
    if (uploadForm) {
        uploadForm.submit();
    }
}

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

document.addEventListener('DOMContentLoaded', function() {
    // Populate the year select options if the element exists
    const yearSelect = document.getElementById('yearSelect');
    if (yearSelect) {
        const currentYear = new Date().getFullYear();
        const startYear = currentYear - 50;
        const endYear = currentYear + 50;

        for (let year = startYear; year <= endYear; year++) {
            const option = document.createElement('option');
            option.value = year;
            option.textContent = year;
            if (year === currentYear) {
                option.selected = true;
            }
            yearSelect.appendChild(option);
        }
    }

    // Handle currency search and filtering if the elements exist
    const searchInput1 = document.getElementById('searchInput1');
    const currencySelect1 = document.getElementById('CurrencySelect1');

    if (searchInput1 && currencySelect1) {
        const originalOptions1 = [...currencySelect1.options];

        searchInput1.addEventListener('input', function() {
            filterOptions(searchInput1, currencySelect1, originalOptions1);
        });

        // Set the favorite currency if available
        const doctorCategory = "{{ favorite_currency }}";
        const options = currencySelect1.options;

        for (let i = 0; i < options.length; i++) {
            if (options[i].value === doctorCategory) {
                options[i].selected = true;
                break;
            }
        }
    }

    // Show the loading overlay on form submission if the form exists
    const submitForm = document.getElementById('submit-form');
    if (submitForm) {
        submitForm.addEventListener('submit', function() {
            showLoadingScreen();
        });
    }
});

// Function to filter the select dropdown based on input
function filterOptions(searchInput, currencySelect, originalOptions) {
    const searchText = searchInput.value.toLowerCase();
    currencySelect.innerHTML = '';

    // Filter from original options
    const filteredOptions = originalOptions.filter(option => {
        const optionText = option.textContent.toLowerCase();
        return optionText.includes(searchText);
    });

    // Add filtered options to the select dropdown
    filteredOptions.forEach(option => {
        currencySelect.appendChild(option);
    });

    // If no options match the filter, add a 'No Match' option
    if (filteredOptions.length === 0) {
        const defaultOption = document.createElement('option');
        defaultOption.disabled = true;
        defaultOption.selected = true;
        defaultOption.textContent = 'No Match';
        currencySelect.appendChild(defaultOption);
    }
}

// Setting the date input to today's date if the element exists
function setTodayDate(dateInputId) {
    const dateInput = document.getElementById(dateInputId);
    if (dateInput) {
        const today = new Date().toISOString().split('T')[0];
        dateInput.value = today;
    }
}

// Pre-select favorite currency in the dropdown if the element exists
function preselectCurrency(selectElementId, favoriteCurrency) {
    const selectElement = document.getElementById(selectElementId);
    if (selectElement) {
        const options = selectElement.options;

        for (let i = 0; i < options.length; i++) {
            if (options[i].value === favoriteCurrency) {
                options[i].selected = true;
                break;
            }
        }
    }
}

// Event listeners
document.addEventListener("DOMContentLoaded", function () {
    const favoriteCurrency = "{{ favorite_currency }}"; // Assuming this is passed in the template

    const searchInput1 = document.getElementById('searchInput1');
    const currencySelect1 = document.getElementById('CurrencySelect1');

    if (searchInput1 && currencySelect1) {
        const originalOptions1 = [...currencySelect1.options];

        // Filter options on search input
        searchInput1.addEventListener('input', () => {
            filterOptions(searchInput1, currencySelect1, originalOptions1);
        });

        // Pre-select favorite currency
        preselectCurrency('CurrencySelect1', favoriteCurrency);
    }

    // Set default date if the element exists
    setTodayDate('dateInput');
});

// Pre-select a value in a dropdown based on a value passed from the server
function preSelectValue(selectElement, value) {
    if (selectElement) {
        const options = selectElement.options;
        for (let i = 0; i < options.length; i++) {
            if (options[i].value === value) {
                options[i].selected = true;
                break;
            }
        }
    }
}

// Add event listener to submit form on select change if the elements exist
function autoSubmitOnChange(selectElement, formId) {
    if (selectElement && document.getElementById(formId)) {
        selectElement.addEventListener("change", function () {
            document.getElementById(formId).submit();
        });
    }
}

// General initialization function
function initializeDropdown(searchInputId, selectElementId, serverValue, formId) {
    const searchInput = document.getElementById(searchInputId);
    const selectElement = document.getElementById(selectElementId);

    if (searchInput && selectElement) {
        const originalOptions = [...selectElement.options];

        searchInput.addEventListener('input', () => {
            filterOptions(searchInput, selectElement, originalOptions);
        });

        if (serverValue) {
            preSelectValue(selectElement, serverValue);
        }

        if (formId) {
            autoSubmitOnChange(selectElement, formId);
        }
    }
}

function copyApiKey() {
    const apiKeyElement = document.getElementById('apiKey');
    if (apiKeyElement) {
        const apiKeyText = apiKeyElement.textContent; // Get the full URL text

        // Create a temporary textarea element to hold the text for copying
        const textarea = document.createElement('textarea');
        textarea.value = apiKeyText; // Set the textarea value to the URL
        document.body.appendChild(textarea); // Append the textarea to the body

        textarea.select(); // Select the text in the textarea
        document.execCommand('copy'); // Copy the selected text to the clipboard
        document.body.removeChild(textarea); // Remove the textarea from the DOM

        alert('API key copied to clipboard!'); // Optional: Alert the user
    }
}

// Landing Page Initialization
document.addEventListener('DOMContentLoaded', function() {
    // Initialize AOS (Animate on Scroll)
    if (typeof AOS !== 'undefined') {
        AOS.init({
            duration: 800,
            easing: 'ease-in-out',
            once: true
        });
    }

    // Update currency symbol based on selected currency
    const fromCurrencySelect = document.getElementById('from_currency');
    if (fromCurrencySelect) {
        fromCurrencySelect.addEventListener('change', function() {
            const currencySymbol = document.getElementById('currency-symbol');
            if (currencySymbol) {
                switch(this.value) {
                    case 'USD': currencySymbol.textContent = '$'; break;
                    case 'EUR': currencySymbol.textContent = '€'; break;
                    case 'GBP': currencySymbol.textContent = '£'; break;
                    case 'JPY': currencySymbol.textContent = '¥'; break;
                    case 'CAD': currencySymbol.textContent = 'CA$'; break;
                    case 'AUD': currencySymbol.textContent = 'A$'; break;
                    case 'CHF': currencySymbol.textContent = 'CHF'; break;
                    case 'CNY': currencySymbol.textContent = '¥'; break;
                    default: currencySymbol.textContent = '$'; break;
                }
            }
        });
    }

    // Language tabs for code examples
    const languageTabs = document.querySelectorAll('.language-tab');
    if (languageTabs.length) {
        languageTabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const lang = tab.getAttribute('data-lang');
                
                // Update active tab
                document.querySelectorAll('.language-tab').forEach(t => {
                    t.classList.remove('active');
                });
                tab.classList.add('active');
                
                // Show the selected code example
                document.querySelectorAll('.code-example').forEach(example => {
                    example.classList.remove('active');
                });
                const activeExample = document.querySelector(`.code-example[data-lang="${lang}"]`);
                if (activeExample) {
                    activeExample.classList.add('active');
                }
            });
        });
    }

    // Copy code example
    const codeCopyBtn = document.querySelector('.code-copy-btn');
    if (codeCopyBtn) {
        codeCopyBtn.addEventListener('click', function() {
            const activeExample = document.querySelector('.code-example.active code');
            if (activeExample) {
                navigator.clipboard.writeText(activeExample.innerText).then(() => {
                    const originalHtml = this.innerHTML;
                    this.innerHTML = '<i class="fas fa-check"></i> Copied!';
                    setTimeout(() => {
                        this.innerHTML = originalHtml;
                    }, 2000);
                }).catch(err => {
                    console.error('Failed to copy: ', err);
                });
            }
        });
    }

    // Copy API response
    const copyResponseBtn = document.getElementById('copy-response');
    if (copyResponseBtn) {
        copyResponseBtn.addEventListener('click', function() {
            const response = document.getElementById('api-response');
            if (response) {
                navigator.clipboard.writeText(response.innerText).then(() => {
                    const originalHtml = this.innerHTML;
                    this.innerHTML = '<i class="fas fa-check"></i>';
                    setTimeout(() => {
                        this.innerHTML = originalHtml;
                    }, 2000);
                }).catch(err => {
                    console.error('Failed to copy response: ', err);
                });
            }
        });
    }

    // Back to top button visibility
    const backToTopBtn = document.getElementById('back-to-top');
    if (backToTopBtn) {
        window.addEventListener('scroll', function() {
            if (window.scrollY > 300) {
                backToTopBtn.classList.add('show');
            } else {
                backToTopBtn.classList.remove('show');
            }
        });

        // Smooth scroll for back to top
        backToTopBtn.addEventListener('click', function(e) {
            e.preventDefault();
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });
    }

    // Counter animation
    const counterElements = document.querySelectorAll('.counter');
    if (counterElements.length) {
        const observerOptions = {
            threshold: 0.5
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const counter = entry.target;
                    const targetValue = parseInt(counter.textContent);
                    let currentValue = 0;
                    const increment = Math.ceil(targetValue / 50);
                    const timer = setInterval(() => {
                        currentValue += increment;
                        if (currentValue >= targetValue) {
                            counter.textContent = targetValue;
                            clearInterval(timer);
                        } else {
                            counter.textContent = currentValue;
                        }
                    }, 30);
                    observer.unobserve(counter);
                }
            });
        }, observerOptions);

        counterElements.forEach(counter => {
            observer.observe(counter);
        });
    }

    // API Demo Form Submission
    const apiDemoForm = document.getElementById('api-demo-form');
    if (apiDemoForm) {
        apiDemoForm.addEventListener('submit', async function (event) {
            event.preventDefault();

            const fromCurrency = document.getElementById('from_currency').value.toUpperCase();
            const toCurrency = document.getElementById('to_currency').value.toUpperCase();
            const amount = parseFloat(document.getElementById('amount').value);
            const spinner = document.getElementById('convert-spinner');
            const responseEl = document.getElementById('api-response');

            if (!fromCurrency || !toCurrency || isNaN(amount)) {
                responseEl.textContent = JSON.stringify({ 
                    error: {
                        code: 400,
                        message: 'Please fill all fields correctly'
                    }
                }, null, 2);
                return;
            }

            // Show loading spinner
            if (spinner) {
                spinner.classList.remove('d-none');
            }
            if (responseEl) {
                responseEl.textContent = 'Loading...';
            }

            try {
                // Get the demo API key from data attribute or use a default
                const apiUrl = document.querySelector('meta[name="api-demo-url"]')?.getAttribute('content') || 
                               'https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/demo/';
                
                const response = await fetch(`${apiUrl}${fromCurrency}`);
                const data = await response.json();

                // Hide spinner after response
                if (spinner) {
                    spinner.classList.add('d-none');
                }

                if (response.ok) {
                    const rate = data.data[toCurrency];
                    const result = amount * rate;

                    // Display the formatted result with timestamps
                    if (responseEl) {
                        responseEl.textContent = JSON.stringify({
                            meta: {
                                base_currency: fromCurrency,
                                target_currency: toCurrency,
                                last_updated_at: new Date().toISOString()
                            },
                            data: {
                                amount: amount,
                                rate: rate,
                                result: parseFloat(result.toFixed(2))
                            }
                        }, null, 2);
                    }
                } else {
                    // Handle API errors with structured error format
                    if (responseEl) {
                        responseEl.textContent = JSON.stringify({
                            error: {
                                code: response.status,
                                message: data.error?.message || 'Failed to fetch exchange rate'
                            }
                        }, null, 2);
                    }
                }
            } catch (error) {
                // Hide spinner and show error
                if (spinner) {
                    spinner.classList.add('d-none');
                }
                
                // Format network errors properly
                if (responseEl) {
                    responseEl.textContent = JSON.stringify({
                        error: {
                            code: 503,
                            message: 'Network error. Please try again later.'
                        }
                    }, null, 2);
                }
            }
        });
    }

    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;
            
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                targetElement.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });
});

// Function to copy text to clipboard with visual feedback
function copyToClipboard(text, elementId) {
    navigator.clipboard.writeText(text).then(() => {
        const element = document.getElementById(elementId);
        if (element) {
            const originalHtml = element.innerHTML;
            element.innerHTML = '<i class="fas fa-check"></i> Copied!';
            setTimeout(() => {
                element.innerHTML = originalHtml;
            }, 2000);
        }
    }).catch(err => {
        console.error('Failed to copy: ', err);
    });
}