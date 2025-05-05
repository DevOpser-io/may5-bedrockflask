// frontend/src/chat.js
import './styles.css';
import { marked } from 'marked';
import DOMPurify from 'dompurify';
import { initMFA } from './mfa';

// Pre-compile marked options
marked.setOptions({
    breaks: true,
    gfm: true,
    headerIds: false,
    mangle: false
});

// Initialize DOMPurify
const purify = DOMPurify(window);

// Configure DOMPurify options
const purifyOptions = {
    ALLOWED_TAGS: [
        'p', 'br', 'b', 'i', 'em', 'strong', 'a', 'ul', 'ol', 'li',
        'code', 'pre', 'h1', 'h2', 'h3', 'blockquote', 'span'
    ],
    ALLOWED_ATTR: ['href', 'target', 'rel', 'class']
};

// Create a main function that will be called on load
function initChat() {
    // Function to cleanup stream connection
    function cleanupStream() {
        if (currentEventSource) {
            console.log('Cleaning up stream connection');
            currentEventSource.close();
            currentEventSource = null;
        }
        if (currentAssistantMessage) {
            currentAssistantMessage = null;
        }
    }

    // Check if we're on a chat page by looking for essential elements
    const chatContainer = document.querySelector('.chat-container');
    const messageForm = document.getElementById('chat-form');
    
    // Only initialize chat functionality if we're on a chat page
    if (!chatContainer || !messageForm) {
        console.log('Not on chat page, skipping chat initialization');
        return; // Exit if we're not on a chat page
    }

    const messageInput = document.getElementById('message-input');
    const clearButton = document.getElementById('clear-btn');
    const stopButton = document.getElementById('stop-btn');
    const newChatButton = document.getElementById('new-chat-btn');
    const tempChatToggle = document.getElementById('temp-chat-toggle');
    
    // Add hamburger menu functionality
    const menuButton = document.querySelector('.menu-button');
    const sidebar = document.querySelector('.sidebar');
    
    if (menuButton && sidebar) {
        menuButton.addEventListener('click', () => {
            sidebar.classList.toggle('active');
        });
    }
    
    let currentEventSource = null;
    let currentAssistantMessage = null;
    let isTemporaryChat = false;

    function appendMessage(role, content) {
        console.log(`Appending message - Role: ${role}, Content length: ${content.length}`);
        
        const roleDiv = document.createElement('div');
        roleDiv.className = `message-role ${role.toLowerCase()}`;
        roleDiv.textContent = role;

        const messageDiv = document.createElement('div');
        messageDiv.className = `${role.toLowerCase()}-message`;
        
        if (role === 'Assistant') {
            // Sanitize and render markdown for assistant messages
            const parsedMarkdown = marked.parse(content);
            console.log('Parsed markdown length:', parsedMarkdown.length);
            
            const cleanHtml = purify.sanitize(parsedMarkdown, purifyOptions);
            console.log('Sanitized HTML length:', cleanHtml.length);
            
            messageDiv.innerHTML = cleanHtml;
        } else {
            messageDiv.textContent = content;
        }

        chatContainer.appendChild(roleDiv);
        chatContainer.appendChild(messageDiv);
        return messageDiv;
    }

    // Shared reset chat function
    async function resetChat() {
        if (currentEventSource) {
            currentEventSource.close();
            currentEventSource = null;
        }
        
        try {
            const response = await fetch('/reset', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    wasTemporary: isTemporaryChat
                })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.success) {
                chatContainer.innerHTML = '';
                currentAssistantMessage = null;
                window.currentConversationId = data.new_conversation_id;
                
                // Only reload conversation history for non-temporary chats
                if (!isTemporaryChat) {
                    loadConversationHistory();
                }
            }
        } catch (error) {
            console.error('Error resetting chat:', error);
            appendMessage('System', 'Failed to reset chat. Please try again.');
        }
    }

    // Handle Enter key press
    messageInput.addEventListener('keydown', function(event) {
        if (event.key === 'Enter' && !event.shiftKey) {
            event.preventDefault();
            document.getElementById('send-btn').click();
        }
    });
    
    // Simplified stop button handler
    stopButton.addEventListener('click', function() {
        if (currentEventSource) {
            currentEventSource.close();
            currentEventSource = null;
            stopButton.disabled = true;
        }
    });
    
    // Use shared resetChat function for both buttons
    clearButton.addEventListener('click', resetChat);
    newChatButton.addEventListener('click', resetChat);
    
    // Temporary chat toggle
    tempChatToggle.addEventListener('change', function() {
        isTemporaryChat = this.checked;
        
        // Clear conversation history display if switching to temporary mode
        if (isTemporaryChat) {
            chatContainer.innerHTML = '';
        } else {
            // Load conversation history when switching back to permanent mode
            loadConversationHistory();
        }
    });

    messageForm.addEventListener('submit', async function(event) {
        event.preventDefault();
        const message = messageInput.value.trim();
        
        if (!message) return;

        try {
            const response = await fetch('/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ 
                    message,
                    isTemporary: isTemporaryChat 
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            messageInput.value = '';
            currentAssistantMessage = null;
            appendMessage('User', message);

            // Simplified stream handling
            if (currentEventSource) {
                currentEventSource.close();
            }

            currentEventSource = new EventSource('/stream');
            stopButton.disabled = false;
            let accumulatedResponse = '';

            currentEventSource.onmessage = (event) => {
                const data = JSON.parse(event.data);
                if (data.content) {
                    accumulatedResponse += data.content;
                    
                    if (!currentAssistantMessage) {
                        currentAssistantMessage = appendMessage('Assistant', accumulatedResponse);
                    } else {
                        const parsedMarkdown = marked.parse(accumulatedResponse);
                        const cleanHtml = purify.sanitize(parsedMarkdown, purifyOptions);
                        currentAssistantMessage.innerHTML = cleanHtml;
                    }
                    
                    chatContainer.scrollTop = chatContainer.scrollHeight;
                }
            };

        } catch (error) {
            console.error('Error:', error);
            appendMessage('System', 'An error occurred. Please try again.');
        }
    });

    // Add event listener for sign out
    document.querySelectorAll('[href*="logout"]').forEach(link => {
        link.addEventListener('click', function(event) {
            cleanupStream();
        });
    });

    // Handle beforeunload to cleanup on page close/refresh
    window.addEventListener('beforeunload', function() {
        cleanupStream();
    });

    function loadConversationHistory() {
        fetch("/conversation_history")
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const conversationList = document.querySelector('.conversation-list');
                    if (!conversationList) return;
                    
                    conversationList.innerHTML = '';
                    
                    const groups = data.history;
                    
                    for (const groupName in groups) {
                        const groupConversations = groups[groupName];
                        if (groupConversations.length > 0) {
                            // Create group header
                            const header = document.createElement('div');
                            header.className = 'conversation-group-header';
                            header.textContent = groupName;
                            conversationList.appendChild(header);
                            
                            // Add conversations
                            groupConversations.forEach(conv => {
                                const item = document.createElement('div');
                                item.className = 'conversation-item';
                                item.dataset.conversationId = conv.id;
                                
                                item.innerHTML = `
                                    <div class="conversation-preview">${conv.preview || 'Empty conversation'}</div>
                                `;
                                
                                item.addEventListener('click', () => loadConversation(conv.id));
                                conversationList.appendChild(item);
                            });
                        }
                    }
                }
            })
            .catch(error => console.error("Error loading conversation history:", error));
    }

    async function loadConversation(conversationId) {
        try {
            // Close any existing stream
            if (currentEventSource) {
                currentEventSource.close();
                currentEventSource = null;
            }

            const response = await fetch(`/get_conversation/${conversationId}`);
            const data = await response.json();
            
            if (data.success) {
                // Clear existing chat
                chatContainer.innerHTML = '';
                currentAssistantMessage = null;
                
                // Load chat history
                data.chat_history.forEach(msg => {
                    appendMessage(
                        msg.role.charAt(0).toUpperCase() + msg.role.slice(1),
                        msg.content
                    );
                });
                
                // Update conversation ID
                window.currentConversationId = data.conversation_id;
                
                // Scroll to bottom
                chatContainer.scrollTop = chatContainer.scrollHeight;
                
                console.log('Successfully loaded conversation:', data.conversation_id);
            } else {
                console.error("Failed to load conversation:", data.error);
                throw new Error(data.error);
            }
        } catch (error) {
            console.error("Error loading conversation:", error);
            appendMessage('System', 'Failed to load conversation. Please try again.');
        }
    }

    // Initial load of conversation history
    loadConversationHistory();
}

// Mobile Navigation Handler
function initMobileNav() {
    const menuButton = document.querySelector('.menu-button');
    const sidebar = document.querySelector('.sidebar');
    let isMenuOpen = false;

    if (!menuButton || !sidebar) return;

    // Toggle menu state with animation handling
    function toggleMenu(show = null) {
        isMenuOpen = show !== null ? show : !isMenuOpen;
        
        if (!isMenuOpen) {
            sidebar.style.transform = 'translateX(-100%)';
            sidebar.classList.remove('active');
        } else {
            sidebar.classList.add('active');
            sidebar.style.transform = 'translateX(0)';
        }
        
        menuButton.setAttribute('aria-expanded', isMenuOpen);
    }

    // Close menu
    function closeMenu() {
        toggleMenu(false);
    }

    // Open menu
    function openMenu() {
        toggleMenu(true);
    }

    // Handle menu button click
    menuButton.addEventListener('click', (e) => {
        e.stopPropagation();
        toggleMenu();
    });

    // Replace the existing loadConversation function
    function loadConversation(conversationId) {
        const chatContainer = document.querySelector('.chat-container');
        if (!chatContainer) return;

        // First close the sidebar
        closeMenu();

        // Show loading state
        chatContainer.innerHTML = '<div class="loading-indicator">Loading conversation...</div>';

        // Load the conversation
        fetch(`/get_conversation/${conversationId}`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    chatContainer.innerHTML = '';
                    
                    // Load chat history
                    data.chat_history.forEach(msg => {
                        const roleDiv = document.createElement('div');
                        roleDiv.className = `message-role ${msg.role === 'user' ? 'user' : ''}`;
                        roleDiv.textContent = msg.role.charAt(0).toUpperCase() + msg.role.slice(1);

                        const messageDiv = document.createElement('div');
                        messageDiv.className = msg.role === 'user' ? 'user-message' : 'assistant-message';
                        messageDiv.innerHTML = msg.role === 'assistant' ? 
                            marked.parse(msg.content) : 
                            msg.content;

                        chatContainer.appendChild(roleDiv);
                        chatContainer.appendChild(messageDiv);
                    });

                    // Update conversation ID
                    window.currentConversationId = data.conversation_id;

                    // Scroll to bottom
                    chatContainer.scrollTop = chatContainer.scrollHeight;
                }
            })
            .catch(error => {
                console.error('Error loading conversation:', error);
                chatContainer.innerHTML = `
                    <div class="system-message error">
                        Failed to load conversation. Please try again.
                    </div>
                `;
            });
    }

    // Add click handlers for conversation items
    document.querySelectorAll('.conversation-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const conversationId = item.dataset.conversationId;
            
            // Update selected state
            document.querySelectorAll('.conversation-item').forEach(i => {
                i.classList.remove('selected');
            });
            item.classList.add('selected');
            
            loadConversation(conversationId);
        });
    });

    // Close menu when clicking outside
    document.addEventListener('click', (e) => {
        if (isMenuOpen && !sidebar.contains(e.target) && e.target !== menuButton) {
            closeMenu();
        }
    });

    // Close menu when window is resized to desktop size
    window.addEventListener('resize', () => {
        if (window.innerWidth >= 768 && isMenuOpen) {
            closeMenu();
        }
    });

    // Handle escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && isMenuOpen) {
            closeMenu();
        }
    });
}

// Add mobile navigation styles
const mobileNavStyles = `
    .loading-indicator {
        padding: 1rem;
        text-align: center;
        color: #6B7280;
    }

    .conversation-item {
        position: relative;
        overflow: hidden;
    }

    .conversation-item.selected {
        background-color: var(--primary-lighter);
        border-left: 3px solid var(--primary-color);
    }

    .sidebar {
        transition: transform 0.3s ease;
    }

    @media (max-width: 768px) {
        .sidebar:not(.active) {
            pointer-events: none;
        }
    }
`;

// Add styles to document
const mobileStyleSheet = document.createElement('style');
mobileStyleSheet.textContent = mobileNavStyles;
document.head.appendChild(mobileStyleSheet);

// Add system message styles
const systemStyles = `
    .system-message {
        padding: 12px 16px;
        margin: 8px 0;
        border-radius: 8px;
        text-align: center;
        font-size: 14px;
    }

    .system-message.error {
        background-color: #FEE2E2;
        color: #991B1B;
        border: 1px solid #FCA5A5;
    }
`;

// Add styles to document
const styleSheet = document.createElement('style');
styleSheet.textContent = systemStyles;
document.head.appendChild(styleSheet);

// Initialize the chat when the DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        initChat();
        initMFA();
        initMobileNav();
        
        // Add flash message handling
        document.addEventListener('click', (e) => {
            if (e.target.matches('.flash .close-button')) {
                const flash = e.target.closest('.flash');
                if (flash) flash.remove();
            }
        });
    });
} else {
    initChat();
    initMFA();
    initMobileNav();
}