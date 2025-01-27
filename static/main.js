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