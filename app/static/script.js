document.addEventListener('DOMContentLoaded', () => {

    let domain = 'http://localhost:5000'; // Default domain

    const cloneVoiceForm = document.getElementById('cloneVoiceForm');
    const ttsForm = document.getElementById('ttsForm'); 
    const selectVoice = document.getElementById('selectVoice');
    const textLanguageSelect = document.getElementById('textLanguage'); // Get language selector
    const textToSpeakArea = document.getElementById('textToSpeak'); // Get textarea
    const audioPlayer = document.getElementById('audioPlayer');
    const audioPlayerContainer = document.getElementById('customAudioPlayerContainer');
    const alertPlaceholder = document.getElementById('alert-placeholder');
    const refreshVoicesBtn = document.getElementById('refreshVoicesBtn');

    function showAlert(message, type = 'danger', duration = 7000) { // Increased default duration
        const wrapper = document.createElement('div');
        wrapper.innerHTML = `
            <div class="alert alert-${type} alert-dismissible fade show" role="alert">
                ${message}
                <button type="button" class="close" data-dismiss="alert" aria-label="Close">
                    <span aria-hidden="true">×</span>
                </button>
            </div>
        `;
        alertPlaceholder.innerHTML = ''; 
        alertPlaceholder.append(wrapper);

        if (duration) {
            setTimeout(() => {
                const alertEl = wrapper.querySelector('.alert');
                if (alertEl && $.fn.alert) { // Check if jQuery and Bootstrap alert plugin are loaded
                     $(alertEl).alert('close');
                } else if (alertEl) {
                    alertEl.remove(); // Fallback if jQuery/Bootstrap JS isn't fully loaded
                }
            }, duration);
        }
    }

    function setButtonLoadingState(button, isLoading, defaultText) {
        const spinner = button.querySelector('.spinner-border');
        const buttonTextNode = Array.from(button.childNodes).find(node => node.nodeType === Node.TEXT_NODE);

        if (isLoading) {
            button.disabled = true;
            if (spinner) spinner.classList.remove('d-none');
            if(buttonTextNode) buttonTextNode.textContent = ' Processing...';

        } else {
            button.disabled = false;
            if (spinner) spinner.classList.add('d-none');
            if(buttonTextNode) buttonTextNode.textContent = ` ${defaultText}`;
        }
    }

    async function loadVoices(selectVoiceIdAfterLoad = null) {
        const originalButtonHTML = refreshVoicesBtn.innerHTML; // Store full HTML to restore icon
        refreshVoicesBtn.disabled = true;
        refreshVoicesBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';

        try {
            const response = await fetch(domain + '/api/v1/video/voices');
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
            }

            const voices = await response.json();
            const previouslySelectedVoice = selectVoice.value; // Remember current selection
            selectVoice.innerHTML = '<option value="">-- Select a Voice --</option>'; 
            if (voices.length === 0) {
                selectVoice.innerHTML = '<option value="">No voices found</option>';
                showAlert('No voices found. Clone one or add via ElevenLabs website.', 'warning');
            } else {
                voices.forEach(voice => {
                    const option = document.createElement('option');
                    option.value = voice.voice_id;
                    let categoryPrefix = voice.category === 'cloned' ? '[Cloned] ' : 
                                         voice.category === 'premade' ? '[Pre-made] ' : 
                                         voice.category ? `[${voice.category}] ` : ''; // Handle other categories
                    option.textContent = `${categoryPrefix}${voice.name}`;
                    selectVoice.appendChild(option);
                });
                if (selectVoiceIdAfterLoad) { // If a new voice was cloned
                    selectVoice.value = selectVoiceIdAfterLoad;
                } else if (previouslySelectedVoice) { // try to reselect previous
                    selectVoice.value = previouslySelectedVoice;
                }
            }
        } catch (error) {
            console.error('Error loading voices:', error);
            showAlert(`Failed to load voices: ${error.message}`, 'warning');
            selectVoice.innerHTML = '<option value="">Error loading voices</option>';
        } finally {
            refreshVoicesBtn.disabled = false;
            refreshVoicesBtn.innerHTML = originalButtonHTML; // Restore original icon
        }
    }

    refreshVoicesBtn.addEventListener('click', () => loadVoices());

    cloneVoiceForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const cloneButton = cloneVoiceForm.querySelector('button[type="submit"]');
        setButtonLoadingState(cloneButton, true, 'Clone Voice');
        audioPlayerContainer.style.display = 'none';
        const formData = new FormData(cloneVoiceForm);
        const files = formData.getAll('files');
        if (files.length === 0 || (files.length === 1 && files[0].name === "" && files[0].size === 0)) {
            showAlert('Please select at least one audio file.', 'warning');
            setButtonLoadingState(cloneButton, false, 'Clone Voice');
            return;
        }
         if (files.some(file => file.size === 0 && file.name !== "")) { // Check for empty files if a name is present
            showAlert('One or more selected files appear to be empty. Please select valid audio files.', 'warning');
            setButtonLoadingState(cloneButton, false, 'Clone Voice');
            return;
        }
        try {
            const response = await fetch(domain + '/api/v1/video/clone-voice', { method: 'POST', body: formData });
            const result = await response.json();
            if (!response.ok) throw new Error(result.message || `HTTP error! status: ${response.status}`);
            showAlert(`Voice "${formData.get('name')}" cloned successfully! Refreshing voice list.`, 'success');
            cloneVoiceForm.reset();
            loadVoices(result.voice_id); 
        } catch (error) {
            console.error('Error cloning voice:', error);
            showAlert(`Error cloning voice: ${error.message}`, 'danger', 10000);
        } finally {
            setButtonLoadingState(cloneButton, false, 'Clone Voice');
        }
    });

    ttsForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const ttsButton = ttsForm.querySelector('button[type="submit"]');
        setButtonLoadingState(ttsButton, true, 'Generate Audio');
        audioPlayerContainer.style.display = 'none';

        const voiceId = selectVoice.value;
        const text = textToSpeakArea.value;
        // const language = textLanguageSelect.value; // Language is not sent directly to API in this setup

        if (!voiceId) {
            showAlert('Please select a voice from the list.', 'warning');
            setButtonLoadingState(ttsButton, false, 'Generate Audio');
            return;
        }
        if (!text.trim()) {
            showAlert('Please enter text to speak.', 'warning');
            setButtonLoadingState(ttsButton, false, 'Generate Audio');
            return;
        }

        try {
            const response = await fetch(domain + '/api/v1/video/tts', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                // body: JSON.stringify({ voice_id: voiceId, text: text, language: language }) // Not sending language
                body: JSON.stringify({ voice_id: voiceId, text: text })
            });

            if (!response.ok) {
                let errorMessage = `HTTP error! status: ${response.status} ${response.statusText}`;
                try { const errorData = await response.json(); errorMessage = errorData.message || errorMessage; } catch (e) {}
                throw new Error(errorMessage);
            }

            const audioBlob = await response.blob();
            if (audioBlob.type !== 'audio/mpeg') { 
                const errorText = await audioBlob.text();
                throw new Error(`Server returned non-audio data. It might be an error message: ${errorText.substring(0,200)}`);
            }
            const audioUrl = URL.createObjectURL(audioBlob);
            audioPlayer.src = audioUrl;
            audioPlayerContainer.style.display = 'block';
        } catch (error) {
            console.error('Error generating speech:', error);
            const err = error.message? error.message : error.toString();
            showAlert(`Error generating speech: ${err}`, 'danger', 10000);
        } finally {
            setButtonLoadingState(ttsButton, false, 'Generate Audio');
        }
    });

    // Update placeholder text based on selected language
    textLanguageSelect.addEventListener('change', (event) => {
        const lang = event.target.value;
        if (lang === 'pt') {
            textToSpeakArea.placeholder = "Digite o texto em Português aqui...";
        } else if (lang === 'en') {
            textToSpeakArea.placeholder = "Enter text in English here...";
        } else if (lang === 'es') {
            textToSpeakArea.placeholder = "Ingrese el texto en Español aquí...";
        } else {
            textToSpeakArea.placeholder = "Enter text here...";
        }
    });

    // Initial load
    loadVoices();
    // Set initial placeholder based on default selected language (Portuguese)
    textToSpeakArea.placeholder = "Digite o texto em Português aqui...";
});