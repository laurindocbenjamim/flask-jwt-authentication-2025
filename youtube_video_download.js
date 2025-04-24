



class YouTubeDownloader {
    constructor() {

        this.baseURL = window.location.origin.includes('laurindocbenjamim.github.io')
            ? window.location.origin + '/laurindo-c-benjamim-portfolio'
            : window.location.origin;

        this.serverDomain = 'http://localhost:5000';

        if (this.baseURL.includes('.github.io') || this.baseURL.includes('laurindocbenjamim.pt')) {
            this.serverDomain = 'https://www.d-tuning.com';
        }

        // Ensure DOM is ready before initializing
        document.addEventListener('DOMContentLoaded', () => {
            

            this.userId = `user_${Math.random().toString(36).substr(2, 9)}`;
            this.initElements();
            this.bindEvents();
            this.toggleAudioExtract(); // Initialize the audio extract toggle
        });

       
    }

    initElements() {
        // Form elements
        this.form = document.getElementById('downloadForm');
        this.urlInput = document.getElementById('videoUrl');
        this.formatRadios = document.querySelectorAll('input[name="format"]');
        this.extractAudio = document.getElementById('extractAudio');
        this.speechToText = document.getElementById('speechToText');
        this.submitBtn = document.getElementById('submitBtn');
        
        // Status elements
        this.loadingSpinner = document.getElementById('loadingSpinner');
        this.progressText = document.getElementById('progressText');
        this.errorAlert = document.getElementById('errorAlert');
        
        // Result elements
        this.resultSection = document.getElementById('resultSection');
        this.resultTitle = document.getElementById('resultTitle');
        this.resultThumbnail = document.getElementById('resultThumbnail');
        this.resultDuration = document.getElementById('resultDuration');
        this.downloadButtons = document.getElementById('downloadButtons');
        
        // Transcript elements
        this.transcriptContainer = document.getElementById('transcriptContainer');
        this.transcriptText = document.getElementById('transcriptText');
        this.copyBtn = document.getElementById('copyTranscriptBtn');
        
        // Auth elements
        this.authContainer = document.getElementById('authContainer');
        this.cookieUpload = document.getElementById('cookieUpload');
        this.cookieInput = document.getElementById('cookieInput');
        this.retryBtn = document.getElementById('retryBtn');
    }

    bindEvents() {
        if (this.form) {
            this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        }

        this.formatRadios.forEach(radio => {
            radio.addEventListener('change', () => this.toggleAudioExtract());
        });

        if (this.copyBtn) {
            this.copyBtn.addEventListener('click', () => this.copyTranscript());
        }

        if (this.cookieUpload && this.cookieInput) {
            this.cookieUpload.addEventListener('click', () => this.cookieInput.click());
            this.cookieInput.addEventListener('change', (e) => this.handleCookieUpload(e));
        }

        if (this.retryBtn) {
            this.retryBtn.addEventListener('click', () => this.retryDownload());
        }
    }

    async handleSubmit(e) {
        e.preventDefault();
        this.showLoading();
        this.hideError();

        try {
            const response = await this.downloadVideo();
            const data = await response.json();

            if (!response.ok) {
                if (data.auth_required) {
                    this.showAuthRequired(data);
                    return;
                }
                throw new Error(data.error || 'Download failed');
            }

            this.displayResults(data);
        } catch (error) {
            this.showError(error.message);
        } finally {
            this.hideLoading();
        }
    }

    showLoading() {
       // if (this.submitBtn) this.submitBtn.disabled = true;
        if (this.loadingSpinner) this.loadingSpinner.style.display = 'inline-block';
        if (this.progressText) this.progressText.style.display = 'inline';
    }

    hideLoading() {
       // if (this.submitBtn) this.submitBtn.disabled = false;
        if (this.loadingSpinner) this.loadingSpinner.style.display = 'none';
        if (this.progressText) this.progressText.style.display = 'none';
    }

    showError(message) {
        if (this.errorAlert) {
            this.errorAlert.textContent = message;
            this.errorAlert.style.display = 'block';
        }
    }

    hideError() {
        if (this.errorAlert) {
            this.errorAlert.style.display = 'none';
        }
    }

    async handleSubmit(e) {
        e.preventDefault();
        this.showLoading();
        this.hideError();

        try {
            const response = await this.downloadVideo();
            const data = await response.json();
            console.log(data)
            if (!response.ok) {
                if (data.auth_required) {
                    this.showAuthRequired(data);
                    return;
                }
                throw new Error(data.error || 'Download failed');
            }

            this.displayResults(data);
        } catch (error) {
            this.showError(error.message);
        } finally {
            this.hideLoading();
        }
    }

    async downloadVideo() {
        return fetch(this.serverDomain + '/api/v1/video/download', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: this.urlInput.value,
                format: document.querySelector('input[name="format"]:checked').value,
                extract_audio: this.extractAudio.checked,
                speech_to_text: this.speechToText.checked,
                user_id: this.userId
            })
        });
    }

    displayResults(data) {
        this.clearResults();

        // Set basic info
        document.getElementById('resultTitle').textContent = data.title || 'Downloaded Content';
        document.getElementById('resultThumbnail').src = data.thumbnail || '';
        document.getElementById('resultDuration').textContent = this.formatDuration(data.duration);

        // Create download buttons
        console.log(data.files)
        data.files.forEach(file => {
            this.createDownloadButton(file);

            if (file.type === 'transcript') {
                this.showTranscript(file.text);
            }
        });

        this.resultSection.style.display = 'block';
    }

    createDownloadButton(file) {
        const btn = document.createElement('a');
        btn.href = `${this.serverDomain}/api/v1/video/download/${encodeURIComponent(file.filename)}`;
        btn.className = 'btn btn-outline-primary me-2 mb-2';
        btn.innerHTML = `<i class="bi bi-download me-1"></i> ${this.capitalize(file.type)} (${file.size_mb}MB)`;
        btn.download = file.filename;
        btn.target = '_blank';
        this.downloadButtons.appendChild(btn);
    }

    showAuthRequired(data) {
        this.authContainer.innerHTML = `
            <div class="alert alert-warning">
                <i class="bi bi-exclamation-triangle me-2"></i>
                ${data.solution.description}
            </div>
            <div class="mt-3">
                <ol class="small">
                    ${data.solution.instructions.map(i => `<li>${i}</li>`).join('')}
                </ol>
                <a href="${data.solution.extension_url}" target="_blank" class="btn btn-sm btn-outline-primary me-2">
                    <i class="bi bi-download me-1"></i> Get Extension
                </a>
                <button id="cookieUpload" class="btn btn-sm btn-primary">
                    <i class="bi bi-upload me-1"></i> Upload Cookies
                </button>
                <input type="file" id="cookieInput" accept=".txt" class="d-none">
            </div>
        `;
        this.authContainer.style.display = 'block';

        // Re-bind events for dynamically created elements
        document.getElementById('cookieUpload').addEventListener('click', () => {
            document.getElementById('cookieInput').click();
        });
        document.getElementById('cookieInput').addEventListener('change', (e) => this.handleCookieUpload(e));
    }

    async handleCookieUpload(event) {
        const file = event.target.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append('cookies_file', file);
        formData.append('user_id', this.userId);

        try {
            const response = await fetch(this.serverDomain + '/api/v1/video/upload-cookies', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Failed to upload cookies');
            }

            this.showMessage('Cookies uploaded successfully! Click "Retry Download"');
            document.getElementById('retryBtn').style.display = 'inline-block';
        } catch (error) {
            this.showError(error.message);
        }
    }

    retryDownload() {
        this.authContainer.style.display = 'none';
        this.form.dispatchEvent(new Event('submit'));
    }

    showTranscript(text) {
        this.transcriptText.textContent = text;
        this.transcriptContainer.style.display = 'block';
    }

    async copyTranscript() {
        try {
            await navigator.clipboard.writeText(this.transcriptText.textContent);
            this.copyBtn.innerHTML = '<i class="bi bi-check"></i> Copied!';
            setTimeout(() => {
                this.copyBtn.innerHTML = '<i class="bi bi-clipboard"></i> Copy';
            }, 2000);
        } catch (err) {
            this.showError('Failed to copy transcript '+err);
        }
    }

    toggleAudioExtract() {
        const isMp3 = document.querySelector('input[name="format"]:checked').value === 'mp3';
        this.extractAudio.checked = isMp3;
        //this.extractAudio.setAttribute('disabled', isMp3);
    }

    showLoading() {
        //this.submitBtn.disabled = true;
        this.loadingSpinner.style.display = 'inline-block';
        this.progressText.style.display = 'inline';
    }

    hideLoading() {
        //this.submitBtn.disabled = false;
        this.loadingSpinner.style.display = 'none';
        this.progressText.style.display = 'none';
    }

    showError(message) {
        this.errorAlert.textContent = message;
        this.errorAlert.style.display = 'block';
    }

    hideError() {
        this.errorAlert.style.display = 'none';
    }

    showMessage(message) {
        const alert = document.createElement('div');
        alert.className = 'alert alert-success mt-3';
        alert.innerHTML = `<i class="bi bi-check-circle me-2"></i> ${message}`;
        this.authContainer.appendChild(alert);
    }

    clearResults() {
        this.downloadButtons.innerHTML = '';
        this.transcriptContainer.style.display = 'none';
        this.resultSection.style.display = 'none';
    }

    formatDuration(seconds) {
        if (!seconds) return '';
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;
        return [hours > 0 ? `${hours}h` : null, minutes > 0 ? `${minutes}m` : null, `${secs}s`]
            .filter(Boolean).join(' ');
    }

    capitalize(str) {
        return str.charAt(0).toUpperCase() + str.slice(1);
    }
}

// Safe initialization
 try {
        new YouTubeDownloader();
    } catch (error) {
        console.error('Initialization error:', error);
        const errorDisplay = document.getElementById('errorAlert') || document.body;
        errorDisplay.textContent = 'Failed to initialize application. Please refresh the page.';
    }
