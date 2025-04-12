

document.addEventListener('DOMContentLoaded', function() {

    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute("content");
    const chatbox = document.getElementById('chatbox');
    const userInput = document.getElementById('user-prompt');
    const sendButton = document.getElementById('send-prompt');

    async function promptAI(prompt){
        //endpoint = `${window.location.origin}/data-science/code-suggestion`;
        endpoint = `${window.location.origin}/ai/dev-ai`;

        const headers = new Headers()
        headers.append('X-CSRF-Token', csrfToken)
        headers.append("Authorization", ` Bearer ${csrfToken}`);

        const formData = new FormData()
        formData.append('prompt', prompt)
        
        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: headers,
                body: formData
            });
            const data = await response.json();
            
            return data
        } catch (error) {
            console.error('Error fetching suggestion:', error);
            return false
        }
    }

    let count_request=0
    function addMessage(message, isUser = false) {
        count_request+=1;
        message = String(message).replace('```', '')
        message = String(message).replace('```', '')

        const messageElement = document.createElement('div');
        const editor = messageElement.cloneNode(true)

        const newId = `editor${count_request}`
        editor.id = newId;

        messageElement.classList.add('message');
        messageElement.classList.add(isUser ? 'user-message' : 'bot-message');
        messageElement.textContent = message;

        chatbox.appendChild(messageElement);
        
        chatbox.scrollTop = chatbox.scrollHeight;        

    }

    function createSmalCodeEditor(id,language, content){
        
        // Initialize Ace Editor
        var editor = ace.edit(`${id}`);
        editor.setTheme("ace/theme/monokai");
        editor.session.setMode(`ace/mode/${language}`);

        editor.setValue(content);
    }

    async function botResponse(message) {
        /*const lowerMessage = message.toLowerCase();
        if (lowerMessage.includes('experience')) {
            return "John has over 5 years of experience in software engineering, specializing in full-stack development. He has worked on various projects involving JavaScript, React, Node.js, and Python.";
        } else if (lowerMessage.includes('project')) {
            return "John has worked on several exciting projects, including a scalable e-commerce platform and a machine learning-powered recommendation system. You can find more details on the Projects page.";
        } else if (lowerMessage.includes('skill') || lowerMessage.includes('technology')) {
            return "John's core skills include JavaScript, React, Node.js, Python, Django, SQL, MongoDB, AWS, Docker, and Git. He's also proficient in RESTful APIs and Agile methodologies.";
        } else if (lowerMessage.includes('contact') || lowerMessage.includes('hire')) {
            return "You can contact John via email at john.doe@example.com or connect with him on LinkedIn. He's always open to new opportunities and collaborations!";
        } else if (lowerMessage.includes('hello') || lowerMessage.includes('hi')) {
            return "Hello! I'm John's portfolio chatbot. How can I assist you today?";
        } else {
            return "I'm sorry, I don't have specific information about that. Is there anything else you'd like to know about John's experience, projects, or skills?";
        }*/
        const response = await promptAI(message) 
        if(Array.isArray(response)){
            console.log(response[0].response)
            addMessage(response[0].response);
        }else{
            addMessage("Process finished!");
        }
        //return "Process finished!"
        
    }

    function handleUserInput() {
        const message = userInput.value.trim();
        if (message) {
            addMessage(message, true);
            userInput.value = '';
            setTimeout(() => {
                //const response = botResponse(message);
                botResponse(message);
                
                //addMessage(response);
            }, 500);
        }
    }

    
    sendButton.addEventListener('click', handleUserInput);
    userInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            handleUserInput();
        }
    });

    // Initial bot message
    addMessage("Hello! I'm Laurindo's portfolio chatbot. How can I help you today?");
});