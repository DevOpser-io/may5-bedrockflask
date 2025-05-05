// Set up CSRF token for AJAX requests
document.addEventListener('DOMContentLoaded', function() {
    // Get CSRF token from meta tag
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

    // Add CSRF token to all AJAX requests
    const originalFetch = window.fetch;
    window.fetch = function() {
        let [resource, config] = arguments;
        if(config === undefined) {
            config = {};
        }
        if(config.headers === undefined) {
            config.headers = {};
        }
        // Add CSRF token to headers if not already present
        if(!config.headers['X-CSRFToken']) {
            config.headers['X-CSRFToken'] = csrfToken;
        }
        return originalFetch(resource, config);
    };

    // For XMLHttpRequest (if used)
    const originalXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function() {
        const xhr = new originalXHR();
        const originalOpen = xhr.open;
        xhr.open = function() {
            const result = originalOpen.apply(this, arguments);
            this.setRequestHeader('X-CSRFToken', csrfToken);
            return result;
        };
        return xhr;
    };
});
