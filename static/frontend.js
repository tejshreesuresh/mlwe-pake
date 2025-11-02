/**
 * Frontend JavaScript for MLWE-PAKE Group Authentication Dashboard
 * Handles WebSocket connections, displays live metrics, and manages groups
 */

let ws = null;
let userId = null;
let metricsInterval = null;

// WebSocket connection management
function connect() {
    userId = document.getElementById('userIdInput').value || 'user_' + Date.now();
    
    if (ws && ws.readyState === WebSocket.OPEN) {
        console.log('Already connected');
        return;
    }
    
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/${userId}`;
    
    ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
        updateConnectionStatus('Connected', 'green');
        console.log('WebSocket connected');
        startMetricsPolling();
        // Request connected users count
        updateConnectedUsers();
    };
    
    ws.onmessage = (event) => {
        const message = JSON.parse(event.data);
        handleMessage(message);
    };
    
    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        updateConnectionStatus('Error', 'red');
    };
    
    ws.onclose = () => {
        updateConnectionStatus('Disconnected', 'red');
        console.log('WebSocket disconnected');
        stopMetricsPolling();
    };
}

function disconnect() {
    if (ws) {
        ws.close();
        ws = null;
    }
    updateConnectionStatus('Disconnected', 'red');
    stopMetricsPolling();
}

function updateConnectionStatus(status, color) {
    const statusDiv = document.getElementById('connectionStatus');
    statusDiv.textContent = `Status: ${status}`;
    statusDiv.style.color = color;
}

// Message handling
function handleMessage(message) {
    const messagesDiv = document.getElementById('messages');
    
    // Format timestamp - use message timestamp if available, otherwise use current time
    let displayTimestamp;
    if (message.timestamp) {
        const date = new Date(message.timestamp * 1000);
        displayTimestamp = date.toLocaleTimeString() + '.' + Math.floor((message.timestamp % 1) * 1000).toString().padStart(3, '0');
    } else {
        displayTimestamp = new Date().toLocaleTimeString();
    }
    
    // Special handling for protocol steps
    if (message.type === 'protocol_step') {
        const stepDiv = document.createElement('div');
        stepDiv.className = 'protocol-step';
        
        // Color code based on step type
        let stepColor = '#3498db'; // Default blue
        if (message.step.includes('ERROR')) stepColor = '#e74c3c';
        else if (message.step.includes('COMPLETE')) stepColor = '#27ae60';
        else if (message.step.includes('HISTORY_EXCLUSION') || message.step.includes('FORWARD_SECRECY')) stepColor = '#9b59b6';
        else if (message.step.includes('RATCHET')) stepColor = '#f39c12';
        
        stepDiv.innerHTML = `
            <div class="step-header">
                <span class="timestamp">[${displayTimestamp}]</span>
                <span class="step-name" style="color: ${stepColor}; font-weight: bold;">${message.step}</span>
            </div>
            <div class="step-message">${message.message}</div>
            ${message.epoch !== undefined ? `<div class="step-details">Epoch: ${message.epoch}${message.previous_epoch !== undefined ? ` (previous: ${message.previous_epoch})` : ''}</div>` : ''}
        `;
        
        messagesDiv.insertBefore(stepDiv, messagesDiv.firstChild);
        
        // Keep only last 50 protocol steps
        while (messagesDiv.children.length > 50) {
            messagesDiv.removeChild(messagesDiv.lastChild);
        }
        
        return; // Don't process as regular message
    }
    
    // Regular message handling
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message';
    
    // Enhanced display for specific message types
    let displayContent = '';
    if (message.type === 'joined_group') {
        displayContent = `
            <div class="message-header">
                <span class="timestamp">[${displayTimestamp}]</span>
                <span class="message-type" style="color: #27ae60;">${message.type}</span>
            </div>
            <div class="message-body">
                <strong>Group:</strong> ${message.group_id}<br>
                <strong>Members:</strong> ${message.member_count}<br>
                <strong>Epoch:</strong> ${message.epoch || 'N/A'}<br>
                ${message.can_decrypt_from_epoch ? `<strong>History Exclusion:</strong> Can decrypt from epoch ${message.can_decrypt_from_epoch} onwards` : ''}
            </div>
        `;
        updateGroupStatus(`Joined group: ${message.group_id} (${message.member_count} members, epoch ${message.epoch || 'N/A'})`, 'green');
    } else if (message.type === 'left_group') {
        displayContent = `
            <div class="message-header">
                <span class="timestamp">[${displayTimestamp}]</span>
                <span class="message-type" style="color: #e67e22;">${message.type}</span>
            </div>
            <div class="message-body">
                <strong>Group:</strong> ${message.group_id}<br>
                ${message.message || ''}
            </div>
        `;
        updateGroupStatus(`Left group: ${message.group_id}`, 'orange');
    } else if (message.type === 'group_key_established') {
        displayContent = `
            <div class="message-header">
                <span class="timestamp">[${displayTimestamp}]</span>
                <span class="message-type" style="color: #27ae60;">${message.type}</span>
            </div>
            <div class="message-body">
                <strong>Group:</strong> ${message.group_id}<br>
                <strong>Members:</strong> ${message.member_count}<br>
                <strong>Epoch:</strong> ${message.epoch || 'N/A'}
            </div>
        `;
        updateGroupStatus(`Group key established for: ${message.group_id} (epoch ${message.epoch || 'N/A'})`, 'green');
    } else if (message.type === 'group_message') {
        displayContent = `
            <div class="message-header">
                <span class="timestamp">[${displayTimestamp}]</span>
                <span class="message-type">${message.type}</span>
                <span class="user-id">From: ${message.user_id}</span>
            </div>
            <div class="message-body">
                ${message.message}<br>
                ${message.epoch !== undefined ? `<small>Epoch: ${message.epoch}</small>` : ''}
            </div>
        `;
    } else {
        // Generic message display
        displayContent = `
            <span class="timestamp">[${displayTimestamp}]</span>
            <span class="message-type">${message.type}</span>
            <pre>${JSON.stringify(message, null, 2)}</pre>
        `;
    }
    
    messageDiv.innerHTML = displayContent;
    messagesDiv.insertBefore(messageDiv, messagesDiv.firstChild);
    
    // Keep only last 50 messages
    while (messagesDiv.children.length > 50) {
        messagesDiv.removeChild(messagesDiv.lastChild);
    }
}

// Group management
function joinGroup() {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        alert('Please connect first');
        return;
    }
    
    const groupId = document.getElementById('groupIdInput').value;
    const password = document.getElementById('passwordInput').value;
    
    if (!groupId) {
        alert('Please enter a group ID');
        return;
    }
    
    ws.send(JSON.stringify({
        type: 'join_group',
        group_id: groupId,
        password: password
    }));
}

function leaveGroup() {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        alert('Please connect first');
        return;
    }
    
    const groupId = document.getElementById('groupIdInput').value;
    
    if (!groupId) {
        alert('Please enter a group ID');
        return;
    }
    
    ws.send(JSON.stringify({
        type: 'leave_group',
        group_id: groupId
    }));
}

function updateGroupStatus(message, color) {
    const statusDiv = document.getElementById('groupStatus');
    statusDiv.textContent = message;
    statusDiv.style.color = color;
}

// Metrics polling
function startMetricsPolling() {
    updateMetrics(); // Initial update
    metricsInterval = setInterval(() => {
        updateMetrics();
        updateConnectedUsers(); // Also update user count
    }, 1000); // Update every second
}

// Update connected users count
async function updateConnectedUsers() {
    try {
        const response = await fetch('/api/groups');
        const data = await response.json();
        const userCountElement = document.getElementById('userCount');
        if (userCountElement) {
            userCountElement.textContent = data.total_users || 0;
        }
    } catch (error) {
        console.error('Error fetching user count:', error);
    }
}

function stopMetricsPolling() {
    if (metricsInterval) {
        clearInterval(metricsInterval);
        metricsInterval = null;
    }
}

async function updateMetrics() {
    try {
        const response = await fetch('/api/metrics');
        const metrics = await response.json();
        
        displayMetrics(metrics);
    } catch (error) {
        console.error('Error fetching metrics:', error);
    }
}

function displayMetrics(metrics) {
    const metricsDiv = document.getElementById('metrics');
    
    if (Object.keys(metrics).length === 0) {
        metricsDiv.innerHTML = '<p style="color: #00ff00;">No metrics available yet</p>';
        return;
    }
    
    let html = '<table class="metrics-table">';
    html += '<tr><th>Operation</th><th>Count</th><th>Avg (ms)</th><th>Min (ms)</th><th>Max (ms)</th><th>Throughput (B/s)</th><th>Success Rate</th></tr>';
    
    for (const [operation, data] of Object.entries(metrics)) {
        html += `
            <tr>
                <td><strong>${operation}</strong></td>
                <td>${data.count}</td>
                <td>${data.avg_time_ms.toFixed(2)}</td>
                <td>${data.min_time_ms.toFixed(2)}</td>
                <td>${data.max_time_ms.toFixed(2)}</td>
                <td>${data.throughput_bps.toFixed(2)}</td>
                <td>${data.success_rate.toFixed(1)}%</td>
            </tr>
        `;
    }
    
    html += '</table>';
    metricsDiv.innerHTML = html;
}

// Send group message
function sendGroupMessage() {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        alert('Please connect first');
        return;
    }
    
    const groupId = document.getElementById('groupIdForMessage').value;
    const message = document.getElementById('messageInput').value;
    
    if (!groupId) {
        alert('Please enter a group ID');
        return;
    }
    
    if (!message.trim()) {
        alert('Please enter a message');
        return;
    }
    
    ws.send(JSON.stringify({
        type: 'group_message',
        group_id: groupId,
        message: message
    }));
    
    // Clear input
    document.getElementById('messageInput').value = '';
    
    // Show in messages panel
    log(`Sent message to group ${groupId}: ${message}`);
}

// Allow Enter key to send message
document.addEventListener('DOMContentLoaded', () => {
    console.log('MLWE-PAKE Dashboard loaded');
    
    // Add Enter key listener for message input
    const messageInput = document.getElementById('messageInput');
    if (messageInput) {
        messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                sendGroupMessage();
            }
        });
    }
});

// Helper function to add log entries
function log(message) {
    const messagesDiv = document.getElementById('messages');
    const timestamp = new Date().toLocaleTimeString();
    
    const logDiv = document.createElement('div');
    logDiv.className = 'message';
    logDiv.innerHTML = `
        <span class="timestamp">[${timestamp}]</span>
        <span class="message-type">INFO</span>
        <span>${message}</span>
    `;
    
    messagesDiv.insertBefore(logDiv, messagesDiv.firstChild);
    
    // Keep only last 100 messages
    while (messagesDiv.children.length > 100) {
        messagesDiv.removeChild(messagesDiv.lastChild);
    }
}

