// Global WebSocket instance
let chatSocket = null;
// Currently active conversation id for chats (user or group)
let activeConversationId = null;

// Search/filter user or group list
function searchUser() {
    const input = document.getElementById('serachChatUser');
    const filter = input.value.toLowerCase();
    const listItems = document.querySelectorAll('.chat-user-list li');

    listItems.forEach(item => {
        const text = item.textContent.toLowerCase();
        item.style.display = text.includes(filter) ? '' : 'none';
    });
}

// Emoji picker basic integration (using emoji-picker-element or custom)
function setupEmojiPicker() {
    const emojiButton = document.getElementById('emojiBtn');
    const messageInput = document.getElementById('messageInput');

    emojiButton.addEventListener('click', () => {
        // Toggle a simple emoji picker panel (implement your own or import)
        // For demo: insert fixed emoji at cursor
        messageInput.value += '😊';
        messageInput.focus();
    });
}


// File upload preview handler
function handleFileUpload(event) {
    const previewArea = document.getElementById('filePreviewArea');
    previewArea.innerHTML = '';  // Clear previous

    const files = event.target.files;
    for (const file of files) {
        const fileType = file.type;
        const div = document.createElement('div');
        div.classList.add('file-preview-card');

        if (fileType.startsWith('image/')) {
            const img = document.createElement('img');
            img.src = URL.createObjectURL(file);
            img.style.maxWidth = '100px';
            div.appendChild(img);
        } else {
            div.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        }

        previewArea.appendChild(div);
    }
}

let mediaRecorder;
let audioChunks = [];

chatSocket = null;  // Your active WebSocket connection

function startRecording() {
    navigator.mediaDevices.getUserMedia({ audio: true }).then(stream => {
        mediaRecorder = new MediaRecorder(stream);
        mediaRecorder.start();
        audioChunks = [];

        mediaRecorder.ondataavailable = event => {
            audioChunks.push(event.data);
        };

        mediaRecorder.onstop = () => {
            const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });

            // Create audio preview
            const audioUrl = URL.createObjectURL(audioBlob);
            const audio = document.createElement('audio');
            audio.controls = true;
            audio.src = audioUrl;
            const preview = document.getElementById('voicePreview');
            preview.innerHTML = '';
            preview.appendChild(audio);

            // Read blob as base64 and send via WebSocket
            const reader = new FileReader();
            reader.onloadend = function() {
                if (chatSocket && chatSocket.readyState === WebSocket.OPEN) {
                    chatSocket.send(JSON.stringify({
                        type: 'file',
                        is_voice: true,
                        file: {
                            name: 'voice_message.webm',
                            content: reader.result.split(',')[1], // base64 content only
                            size: audioBlob.size
                        }
                    }));
                }
            };
            reader.readAsDataURL(audioBlob);
        };
    });
}

function stopRecording() {
    if (mediaRecorder && mediaRecorder.state !== "inactive") {
        mediaRecorder.stop();
    }
}

function addMessageToList(message) {
    const list = document.getElementById('messagesList');
    const li = document.createElement('li');
    li.textContent = `[${message.sender}] ${message.content || ''}`;
    if (message.file) {
        const a = document.createElement('a');
        a.href = message.file;
        a.textContent = ' (View File)';
        a.target = '_blank';
        li.appendChild(a);
    }
    list.appendChild(li);
}

// Modal triggers handled by Bootstrap data-bs-toggle attributes, no extra JS needed.

// Initialization
window.addEventListener('DOMContentLoaded', () => {
    setupEmojiPicker();

    document.getElementById('fileInput').addEventListener('change', handleFileUpload);

    // Replace with real conversation ID
    const activeConversationId = 'bff2c0f3-c33e-4871-9610-87eb64d698ea';
    setupWebSocket(activeConversationId);

    document.getElementById('startRecordingBtn').onclick = startRecording;
    document.getElementById('stopRecordingBtn').onclick = stopRecording;
});


function addMessageToList(message) {
  const list = document.getElementById('messagesList');
  const li = document.createElement('li');
  li.textContent = `[${message.sender}] ${message.content || ''}`;
  if(message.file) {
    const a = document.createElement('a');
    a.href = message.file;
    a.textContent = ' (View File)';
    a.target = '_blank';
    li.appendChild(a);
  }
  list.appendChild(li);
}

window.addEventListener('DOMContentLoaded', () => {
  setupEmojiPicker();
  document.getElementById('fileInput').addEventListener('change', handleFileUpload);
  const convId = 'bff2c0f3-c33e-4871-9610-87eb64d698ea';
  const activeConversationId = convId;
  setupWebSocket(activeConversationId);
  document.getElementById('startRecordingBtn').onclick = startRecording;
  document.getElementById('stopRecordingBtn').onclick = stopRecording;
});




// Keep track of typing timeout per user, debounce sending typing events
let typingTimeout = null;
const TYPING_DELAY = 3000; // 3 seconds without keystroke means stop typing
// const usersTyping = new Set();

// Reference your WebSocket chat connection, assumed initialized as chatSocket
// const chatSocket = ... (initialized from previous code)

function notifyTyping(isTyping) {
  if (chatSocket && chatSocket.readyState === WebSocket.OPEN) {
    chatSocket.send(JSON.stringify({
      type: 'typing',
      is_typing: isTyping
    }));
  }
}

function onUserInput() {
  // The user typed something, send "typing" if not already sent recently
  if (!typingTimeout) {
    notifyTyping(true);
  }
  clearTimeout(typingTimeout);

  // Set timeout to send stop typing event after delay
  typingTimeout = setTimeout(() => {
    notifyTyping(false);
    typingTimeout = null;
  }, TYPING_DELAY);
}

// Update typing indicator UI based on who is typing
function updateTypingIndicator(typingUsersSet) {
  const indicator = document.getElementById('typingStatus');
  if (typingUsersSet.size === 0) {
    indicator.textContent = '';
  } else if (typingUsersSet.size === 1) {
    indicator.textContent = [...typingUsersSet][0] + ' is typing...';
  } else {
    indicator.textContent = 'Several people are typing...';
  }
}

// Manage users currently typing, key: userId, value: timeoutId
const usersTyping = new Map();

function handleIncomingTyping(userId, isTyping) {
  if (isTyping) {
    // Add/refresh user typing status with 5s expiry on receiver side
    if (usersTyping.has(userId)) {
      clearTimeout(usersTyping.get(userId));
    }
    usersTyping.set(userId, setTimeout(() => {
      usersTyping.delete(userId);
      updateTypingIndicator(usersTyping);
    }, 5000));
  } else {
    // Remove user typing state immediately
    if (usersTyping.has(userId)) {
      clearTimeout(usersTyping.get(userId));
      usersTyping.delete(userId);
    }
  }
  updateTypingIndicator(usersTyping);
}

// Mark messages read when visible or clicked, update UI & notify server
function markMessageAsRead(messageId) {
  // Optionally, update UI to show read status
  const msgElem = document.querySelector(`li[data-message-id='${messageId}']`);
  if (msgElem) {
    msgElem.classList.add('read');
  }
  // Send acknowledgement to server/websocket if desired
  if (chatSocket && chatSocket.readyState === WebSocket.OPEN) {
    chatSocket.send(JSON.stringify({
      type: 'read',
      message_id: messageId
    }));
  }
}

// Detect message visibility to mark as read
function setupReadReceipts() {
  const messages = document.querySelectorAll('#messagesList li');
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const msgId = entry.target.dataset.messageId;
        markMessageAsRead(msgId);
      }
    });
  }, { threshold: 1.0 }); // fully visible

  messages.forEach(msg => observer.observe(msg));
}

// Integrate into WebSocket message handler to react to incoming events
function setupChatSocketHandlers() {
  chatSocket.onmessage = function(e) {
    const data = JSON.parse(e.data);
    switch(data.type) {
      case 'message':
        addMessageToList(data);
        break;
      case 'typing':
        handleIncomingTyping(data.typing_user, data.is_typing);
        break;
      case 'read':
        // Optionally update UI for read receipts on messages
        if (data.message_id) {
          const msgElem = document.querySelector(`li[data-message-id='${data.message_id}']`);
          if (msgElem) msgElem.classList.add('read-by-other');
        }
        break;
    }
  };
}

// Hook user input event to typing notification
const messageInput = document.getElementById('messageInput');
if (messageInput) {
  messageInput.addEventListener('input', onUserInput);
}

// After DOM load, setup handlers and existing message read tracking
window.addEventListener('DOMContentLoaded', () => {
  setupChatSocketHandlers();
  setupReadReceipts();
});





// Setup WebSocket connection and message event handling for current conversation
function setupWebSocket(conversationId) {
    activeConversationId = conversationId;
    chatSocket = new WebSocket(`ws://${window.location.host}/ws/chat/${conversationId}/`);

    chatSocket.onopen = () => {
        console.log("WebSocket connection established.");
    };

    chatSocket.onmessage = e => {
        const data = JSON.parse(e.data);
        switch (data.type) {
            case 'message':
                addMessageToList(data);
                break;
            case 'typing':
                handleIncomingTyping(data.typing_user, data.is_typing);
                break;
            case 'read':
                handleReadReceipt(data.message_id, data.user);
                break;
            case 'contact_added':
                addContactToList(data.contact);
                break;
            case 'group_created':
                addGroupToList(data.group);
                break;
            case 'error':
                displayError(data.message);
                break;
            default:
                console.warn("Unknown message type:", data.type);
        }
    };

    chatSocket.onclose = e => {
        console.error('Chat socket closed unexpectedly');
    };
}

// Send JSON message then handle errors internally if socket closed or error occurs
function sendViaSocket(payload) {
    if (chatSocket && chatSocket.readyState === WebSocket.OPEN) {
        chatSocket.send(JSON.stringify(payload));
    } else {
        displayError("WebSocket connection not open.");
    }
}

// Form handlers using event delegation or specific id bindings
function handleAddContactForm(event) {
    event.preventDefault();
    const email = document.getElementById('addcontactemail-input').value.trim();
    const name = document.getElementById('addcontactname-input').value.trim();
    const invitationMessage = document.getElementById('addcontact-invitemessage-input').value.trim();

    if (!email || !name) {
        alert("Please complete all required fields.");
        return;
    }

    sendViaSocket({
        type: "add_contact",
        email,
        name,
        invitation_message: invitationMessage
    });

    // Optionally reset form here if immediate UI update expected
    event.target.reset();
    closeModal("#addContact-exampleModal");
}

function handleCreateGroupForm(event) {
    event.preventDefault();
    const groupName = document.getElementById('addgroupname-input').value.trim();
    const groupDescription = document.getElementById('addgroupdescription-input').value.trim();

    if (!groupName) {
        alert("Please enter a group name.");
        return;
    }

    // Collect selected member IDs checkboxes
    let members = [];
    document.querySelectorAll('#groupmembercollapse input[type=checkbox]:checked').forEach(checkbox => {
        members.push(checkbox.value);
    });

    sendViaSocket({
        type: "create_group",
        group_name: groupName,
        group_description: groupDescription,
        members: members
    });

    event.target.reset();
    closeModal("#addgroup-exampleModal");
}

function handleSendMessageForm(event) {
    event.preventDefault();
    const content = document.getElementById('messageInput').value.trim();
    if (!content) return;

    sendViaSocket({
        type: "send_message",
        content,
        conversation_id: activeConversationId
    });

    // Clear input after sending
    document.getElementById('messageInput').value = "";
}

// Add message item to message list UI
function addMessageToList(message) {
    const list = document.getElementById('messagesList');
    const li = document.createElement('li');
    li.dataset.messageId = message.id || ''; // if server sends id
    li.textContent = `[${message.sender}] ${message.content || ''}`;
    if (message.file) {
        const a = document.createElement('a');
        a.href = message.file;
        a.textContent = ' (View File)';
        a.target = '_blank';
        li.appendChild(a);
    }
    list.appendChild(li);
    scrollChatToBottom();
}

// Add contact to contacts list UI
function addContactToList(contact) {
    const contactsList = document.getElementById('contactsList');
    if (!contactsList) return;

    const li = document.createElement('li');
    li.textContent = contact.display_name || contact.username || "Unnamed";
    contactsList.appendChild(li);
}

// Add group to group/channel list UI
function addGroupToList(group) {
    const groupList = document.getElementById('channelList');
    if (!groupList) return;

    const li = document.createElement('li');
    li.textContent = group.name || "Unnamed Group";
    groupList.appendChild(li);
}

// Show or clear errors on UI
function displayError(msg) {
    alert(msg); // Replace with nicer UI alert/toast as needed
}

// Scroll chat to newest message
function scrollChatToBottom() {
    const container = document.getElementById('messagesList');
    if (container) container.scrollTop = container.scrollHeight;
}



function notifyTyping(isTyping) {
    sendViaSocket({type: "typing", is_typing: isTyping});
}

function onUserInput() {
    if (!typingTimeout) {
        notifyTyping(true);
    }
    clearTimeout(typingTimeout);
    typingTimeout = setTimeout(() => {
        notifyTyping(false);
        typingTimeout = null;
    }, TYPING_DELAY);
}

function handleIncomingTyping(userId, isTyping) {
    if (isTyping) usersTyping.add(userId);
    else usersTyping.delete(userId);

    updateTypingIndicator();
}

function updateTypingIndicator() {
    const indicator = document.getElementById('typingStatus');
    if (usersTyping.size === 0) {
        indicator.textContent = '';
    } else if (usersTyping.size === 1) {
        indicator.textContent = `${[...usersTyping][0]} is typing...`;
    } else {
        indicator.textContent = 'Several people are typing...';
    }
}

// Read receipt logic (optionally implement if required)
function markMessageAsRead(messageId) {
    sendViaSocket({type: "read", message_id: messageId});
}

function handleReadReceipt(messageId, userId) {
    const msgElem = document.querySelector(`li[data-message-id='${messageId}']`);
    if (msgElem) msgElem.classList.add('read-by-other');
}

// Utility: close bootstrap modal by selector
function closeModal(selector) {
    const modal = document.querySelector(selector);
    if (modal) {
        const modalInstance = bootstrap.Modal.getInstance(modal);
        if (modalInstance) modalInstance.hide();
    }
}

// Event listener for initialization on page load
window.addEventListener('DOMContentLoaded', () => {
    // Setup WebSocket with initial active conversation on page load
    const convId = 'bff2c0f3-c33e-4871-9610-87eb64d698ea';

    const initConversationId = convId;
    setupWebSocket(initConversationId);

    // Hook form submit event handlers
    const addContactForm = document.getElementById('addContactForm');
    if (addContactForm) addContactForm.addEventListener('submit', handleAddContactForm);

    const createGroupForm = document.getElementById('createGroupForm');
    if (createGroupForm) createGroupForm.addEventListener('submit', handleCreateGroupForm);

    const sendMessageForm = document.getElementById('sendMessageForm');
    if (sendMessageForm) sendMessageForm.addEventListener('submit', handleSendMessageForm);

    // Chat input typing event for typing indicator
    const messageInput = document.getElementById('messageInput');
    if (messageInput) messageInput.addEventListener('input', onUserInput);
});


function addMessageToList(message) {
    const list = document.getElementById('messagesList');
    const li = document.createElement('li');
    
    li.dataset.messageId = message.id || ''; // attach message id for read tracking
    
    // Basic message content
    li.innerHTML = `
      <span>[${message.sender}]</span>
      <span>${message.content || ''}</span>
      ${message.file ? `<a href="${message.file}" target="_blank">(View File)</a>` : ''}
      <span class="read-status">${message.is_read ? '✔✔' : '✔'}</span>
    `;

    list.appendChild(li);
    scrollChatToBottom();
}

// Update message's read status double checkmark UI
function markMessageReadUI(messageId) {
    const msgElem = document.querySelector(`li[data-message-id='${messageId}']`);
    if (msgElem) {
        const readSpan = msgElem.querySelector('.read-status');
        if (readSpan) readSpan.textContent = '✔✔';  // double check marks
        msgElem.classList.add('read-by-other'); // optional class for styling
    }
}

// Handle read receipt WS event
function handleReadReceipt(messageId, userId) {
    markMessageReadUI(messageId);
}
