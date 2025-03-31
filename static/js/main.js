document.addEventListener('DOMContentLoaded', function() {
    // Check server status on page load
    checkServerStatus();
    
    // Set up periodic status checks
    setInterval(checkServerStatus, 30000); // Check every 30 seconds
});

/**
 * Check the MCP server status and update the status indicator.
 */
function checkServerStatus() {
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            const statusIndicator = document.getElementById('serverStatusIndicator');
            if (!statusIndicator) return;
            
            if (data.fhir_server_configured) {
                if (data.fhir_server_connection === 'connected') {
                    statusIndicator.innerHTML = '<span class="badge bg-success">FHIR Server: Connected</span>';
                } else {
                    statusIndicator.innerHTML = '<span class="badge bg-warning">FHIR Server: Error</span>';
                }
            } else {
                statusIndicator.innerHTML = '<span class="badge bg-secondary">FHIR Server: Not Configured</span>';
            }
        })
        .catch(error => {
            console.error('Error checking server status:', error);
            const statusIndicator = document.getElementById('serverStatusIndicator');
            if (statusIndicator) {
                statusIndicator.innerHTML = '<span class="badge bg-danger">Server Status: Error</span>';
            }
        });
}

/**
 * Format JSON for display with syntax highlighting.
 * 
 * @param {Object} obj - The object to format as JSON
 * @returns {string} HTML-formatted JSON with syntax highlighting
 */
function formatJSON(obj) {
    if (typeof obj !== 'object' || obj === null) {
        return obj;
    }
    
    return JSON.stringify(obj, null, 2)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
            let cls = 'json-number';
            if (/^"/.test(match)) {
                if (/:$/.test(match)) {
                    cls = 'json-key';
                } else {
                    cls = 'json-string';
                }
            } else if (/true|false/.test(match)) {
                cls = 'json-boolean';
            } else if (/null/.test(match)) {
                cls = 'json-null';
            }
            return '<span class="' + cls + '">' + match + '</span>';
        });
}
