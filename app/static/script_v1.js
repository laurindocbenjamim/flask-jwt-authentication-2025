document.addEventListener('DOMContentLoaded', () => {
    let domain = 'http://localhost:5000'; // Default domain

    const cloneVoiceForm = document.getElementById('cloneVoiceForm');
    const ttsForm = document.getElementById('ttsForm');
    const selectVoice = document.getElementById('selectVoice');
    const audioPlayer = document.getElementById('audioPlayer');
    const audioPlayerContainer = document.getElementById('audioPlayerContainer');
    const alertPlaceholder = document.getElementById('alert-placeholder');
    const refreshVoicesBtn = document.getElementById('refreshVoicesBtn');

    function showAlert(message, type = 'danger', duration = 5000) {
        const wrapper = document.createElement('div');
        wrapper.innerHTML = `
            <div class="alert alert-${type} alert-dismissible fade show" role="alert">
                ${message}
                <button type="button" class="close" data-dismiss="alert" aria-label="Close">
                    <span aria-hidden="true">×</span>
                </button>
            </div>
        `;
        // Clear only old alerts of the same type perhaps, or just prepend
        alertPlaceholder.innerHTML = ''; // Simple clear for now
        alertPlaceholder.append(wrapper);

        if (duration) {
            setTimeout(() => {
                const alert = wrapper.querySelector('.alert');
                if (alert) {
                    // Bootstrap's way to close alerts with fade
                    $(alert).alert('close'); 
                }
            }, duration);
        }
    }

    function setButtonLoadingState(button, isLoading, defaultText) {
        const spinner = button.querySelector('.spinner-border');
        if (isLoading) {
            button.disabled = true;
            if (spinner) spinner.classList.remove('d-none');
            button.childNodes[button.childNodes.length -1].textContent = ' Processing...';

        } else {
            button.disabled = false;
            if (spinner) spinner.classList.add('d-none');
            button.childNodes[button.childNodes.length -1].textContent = ` ${defaultText}`;
        }
    }


    // Load voices on page load and on refresh
    async function loadVoices(selectVoiceIdAfterLoad = null) {
        const originalButtonText = refreshVoicesBtn.innerHTML;
        refreshVoicesBtn.disabled = true;
        refreshVoicesBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';

        try {
            const response = await fetch(domain + '/api/v1/video/voices');
            console.log(response)
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
            }
            const voices = await response.json();
            selectVoice.innerHTML = '<option value="">-- Select a Voice --</option>'; 
            if (voices.length === 0) {
                selectVoice.innerHTML = '<option value="">No voices found in your account</option>';
                showAlert('No voices found. Clone one or add via ElevenLabs website.', 'warning');
            } else {
                voices.forEach(voice => {
                    const option = document.createElement('option');
                    option.value = voice.voice_id;
                    let categoryPrefix = voice.category === 'cloned' ? '[Cloned] ' : 
                                         voice.category === 'premade' ? '[Pre-made] ' : '';
                    option.textContent = `${categoryPrefix}${voice.name}`;
                    selectVoice.appendChild(option);
                });
                if (selectVoiceIdAfterLoad) {
                    selectVoice.value = selectVoiceIdAfterLoad;
                }
            }
        } catch (error) {
            console.error('Error loading voices:', error);
            showAlert(`Failed to load voices: ${error.message}`, 'warning');
            selectVoice.innerHTML = '<option value="">Error loading voices</option>';
        } finally {
            refreshVoicesBtn.disabled = false;
            refreshVoicesBtn.innerHTML = originalButtonText;
        }
    }

    refreshVoicesBtn.addEventListener('click', () => loadVoices());

    // Handle Voice Cloning
    cloneVoiceForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const cloneButton = cloneVoiceForm.querySelector('button[type="submit"]');
        setButtonLoadingState(cloneButton, true, 'Clone Voice');
        audioPlayerContainer.style.display = 'none';

        const formData = new FormData(cloneVoiceForm);
        const files = formData.getAll('files');
        if (files.length === 0 || (files.length === 1 && files[0].name === "")) {
            showAlert('Please select at least one audio file.', 'warning');
            setButtonLoadingState(cloneButton, false, 'Clone Voice');
            return;
        }
         if (files.some(file => file.size === 0)) {
            showAlert('One or more selected files are empty. Please select valid audio files.', 'warning');
            setButtonLoadingState(cloneButton, false, 'Clone Voice');
            return;
        }


        try {
            const response = await fetch(domain + '/api/v1/video/clone-voice', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.message || `HTTP error! status: ${response.status}`);
            }
            
            showAlert(`Voice "${formData.get('name')}" cloned successfully! It will appear in the list below.`, 'success');
            cloneVoiceForm.reset();
            loadVoices(result.voice_id); // Refresh voice list and try to select the new one
        } catch (error) {
            console.error('Error cloning voice:', error);
            showAlert(`Error cloning voice: ${error.message}`, 'danger', 10000);
        } finally {
            setButtonLoadingState(cloneButton, false, 'Clone Voice');
        }
    });

    // Handle Text-to-Speech
    ttsForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const ttsButton = ttsForm.querySelector('button[type="submit"]');
        setButtonLoadingState(ttsButton, true, 'Generate Audio');
        audioPlayerContainer.style.display = 'none';

        const voiceId = selectVoice.value;
        const text = document.getElementById('textToSpeak').value;

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
                body: JSON.stringify({ voice_id: voiceId, text: text })
            });

            if (!response.ok) {
                let errorMessage = `HTTP error! status: ${response.status} ${response.statusText}`;
                try {
                    const errorData = await response.json();
                    errorMessage = errorData.message || errorMessage;
                } catch (e) { /* Ignore if not JSON */ }
                throw new Error(errorMessage);
            }

            const audioBlob = await response.blob();
            if (audioBlob.type !== 'audio/mpeg') { // Basic check for non-audio response
                const errorText = await audioBlob.text();
                throw new Error(`Received non-audio response from server: ${errorText.substring(0,100)}`);
            }
            const audioUrl = URL.createObjectURL(audioBlob);
            audioPlayer.src = audioUrl;
            audioPlayerContainer.style.display = 'block';
            // showAlert('Audio generated successfully!', 'success'); // Can be a bit much

        } catch (error) {
            console.error('Error generating speech:', error);
            showAlert(`Error generating speech: ${error.message}`, 'danger', 10000);
        } finally {
            setButtonLoadingState(ttsButton, false, 'Generate Audio');
        }
    });

    // Initial load
    loadVoices();
});