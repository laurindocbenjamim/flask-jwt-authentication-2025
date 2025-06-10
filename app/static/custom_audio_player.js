// Your existing script.js content...

document.addEventListener('DOMContentLoaded', () => {

    const textToSpeakElement = document.getElementById('textToSpeak');
    const currentCharCountElement = document.getElementById('currentCharCount');

    // --- Custom Audio Player Logic ---
    const audioPlayer = document.getElementById('audioPlayer');
    const customPlayerContainer = document.getElementById('customAudioPlayerContainer');
    const playPauseBtn = document.getElementById('playPauseBtn');
    const playIcon = document.getElementById('playIcon');
    const pauseIcon = document.getElementById('pauseIcon');
    const seekBar = document.getElementById('seekBar');
    const currentTimeDisplay = document.getElementById('currentTime');
    const durationDisplay = document.getElementById('duration');
    const volumeBtn = document.getElementById('volumeBtn');
    const volumeIcon = document.getElementById('volumeIcon');
    const volumeMuteIcon = document.getElementById('volumeMuteIcon');
    const volumeBar = document.getElementById('volumeBar');
    const downloadBtn = document.getElementById('downloadBtn'); // Get the download button

    let isSeeking = false;

    function formatTime(seconds) {
        if (isNaN(seconds) || seconds < 0) return '0:00';
        const minutes = Math.floor(seconds / 60);
        const secs = Math.floor(seconds % 60);
        return `${minutes}:${secs < 10 ? '0' : ''}${secs}`;
    }

    function updateSeekBarBackground(element, progressPercentage) {
        // Ensure progressPercentage is a number and within 0-100
        const clampedProgress = Math.max(0, Math.min(100, Number(progressPercentage)));
        element.style.background = `linear-gradient(to right, #007bff ${clampedProgress}%, #ddd ${clampedProgress}%)`;
    }


    if (playPauseBtn) {
        playPauseBtn.addEventListener('click', () => {
            if (audioPlayer.src && (audioPlayer.paused || audioPlayer.ended)) {
                audioPlayer.play();
            } else if (audioPlayer.src) { // Only pause if there's a source
                audioPlayer.pause();
            }
        });
    }

    if (audioPlayer) {
        audioPlayer.addEventListener('play', () => {
            if(playIcon) playIcon.style.display = 'none';
            if(pauseIcon) pauseIcon.style.display = 'block';
        });

        audioPlayer.addEventListener('pause', () => {
            if(playIcon) playIcon.style.display = 'block';
            if(pauseIcon) pauseIcon.style.display = 'none';
        });

        audioPlayer.addEventListener('loadedmetadata', () => {
            if(durationDisplay) durationDisplay.textContent = formatTime(audioPlayer.duration);
            if(seekBar) {
                seekBar.max = audioPlayer.duration;
                seekBar.value = 0;
                updateSeekBarBackground(seekBar, 0);
            }
            if(currentTimeDisplay) currentTimeDisplay.textContent = formatTime(0);
            if(downloadBtn) downloadBtn.disabled = false; // Enable download button
        });

        audioPlayer.addEventListener('timeupdate', () => {
            if (!isSeeking && audioPlayer.duration) { // Ensure duration is available
                if(currentTimeDisplay) currentTimeDisplay.textContent = formatTime(audioPlayer.currentTime);
                if(seekBar) {
                    seekBar.value = audioPlayer.currentTime;
                    const progress = (audioPlayer.currentTime / audioPlayer.duration) * 100;
                    updateSeekBarBackground(seekBar, progress);
                }
            } else if (!audioPlayer.duration && seekBar) { // Handle case where duration might not be set yet
                updateSeekBarBackground(seekBar, 0);
            }
        });

        audioPlayer.addEventListener('ended', () => {
            if(playIcon) playIcon.style.display = 'block';
            if(pauseIcon) pauseIcon.style.display = 'none';
            if(seekBar) {
                seekBar.value = 0;
                updateSeekBarBackground(seekBar, 0);
            }
            if(currentTimeDisplay) currentTimeDisplay.textContent = formatTime(0);
        });

        audioPlayer.addEventListener('volumechange', () => {
            const isMuted = audioPlayer.muted || audioPlayer.volume === 0;
            if (isMuted) {
                if(volumeIcon) volumeIcon.style.display = 'none';
                if(volumeMuteIcon) volumeMuteIcon.style.display = 'block';
            } else {
                if(volumeIcon) volumeIcon.style.display = 'block';
                if(volumeMuteIcon) volumeMuteIcon.style.display = 'none';
            }
            if(volumeBar) {
                volumeBar.value = isMuted ? 0 : audioPlayer.volume;
                const volumeProgress = isMuted ? 0 : (audioPlayer.volume * 100);
                updateSeekBarBackground(volumeBar, volumeProgress);
            }
        });

        // Initially disable download button until audio is loaded
        if(downloadBtn) downloadBtn.disabled = true;
    }

    if (seekBar) {
        seekBar.addEventListener('input', () => {
            isSeeking = true;
            if(currentTimeDisplay) currentTimeDisplay.textContent = formatTime(parseFloat(seekBar.value));
            if (audioPlayer.duration) {
                const progress = (parseFloat(seekBar.value) / audioPlayer.duration) * 100;
                updateSeekBarBackground(seekBar, progress);
            } else {
                updateSeekBarBackground(seekBar, 0);
            }
        });
        seekBar.addEventListener('change', () => {
            if (audioPlayer.src) { // Only seek if there's a source
                audioPlayer.currentTime = parseFloat(seekBar.value);
                isSeeking = false;
                if (!audioPlayer.paused) {
                    audioPlayer.play();
                }
            }
        });
        updateSeekBarBackground(seekBar, 0);
    }

    if (volumeBtn) {
        volumeBtn.addEventListener('click', () => {
            if (audioPlayer.src) { // Only toggle mute if there's a source
                 audioPlayer.muted = !audioPlayer.muted;
            }
        });
    }

    if (volumeBar) {
        volumeBar.addEventListener('input', (e) => {
             if (audioPlayer.src) { // Only change volume if there's a source
                audioPlayer.muted = false;
                audioPlayer.volume = parseFloat(e.target.value);
             } else {
                e.target.value = 1; // Reset if no audio
             }
        });
        const initialVolumeProgress = (audioPlayer && audioPlayer.src) ? audioPlayer.volume * 100 : 100;
        updateSeekBarBackground(volumeBar, initialVolumeProgress);
        volumeBar.value = (audioPlayer && audioPlayer.src) ? audioPlayer.volume : 1;
        if (audioPlayer && audioPlayer.src) {
            const event = new Event('volumechange');
            audioPlayer.dispatchEvent(event);
        }
    }

    // --- Download Button Logic ---
    if (downloadBtn) {
        downloadBtn.addEventListener('click', () => {
            if (!audioPlayer.src || audioPlayer.src === window.location.href) { // Check if src is valid
                console.warn("No audio source to download.");
                alert("No audio loaded to download."); // Or some other user feedback
                return;
            }

            const audioSrc = audioPlayer.src;
            const defaultFilename = "generated_audio.mp3"; // Default filename

            // Try to get filename from URL if possible
            let filename = defaultFilename;
            try {
                const url = new URL(audioSrc);
                const pathSegments = url.pathname.split('/');
                const lastSegment = pathSegments[pathSegments.length - 1];
                if (lastSegment && lastSegment.includes('.')) { // Basic check for a file extension
                    filename = lastSegment;
                }
            } catch (e) {
                console.warn("Could not parse audio source URL for filename, using default.");
            }
            
            // If the src is a blob URL, we might need to fetch it first to download properly with a name
            if (audioSrc.startsWith('blob:')) {
                fetch(audioSrc)
                    .then(response => response.blob())
                    .then(blob => {
                        const link = document.createElement('a');
                        link.href = URL.createObjectURL(blob);
                        link.download = filename;
                        document.body.appendChild(link);
                        link.click();
                        document.body.removeChild(link);
                        URL.revokeObjectURL(link.href); // Clean up blob URL
                    })
                    .catch(err => {
                        console.error("Error downloading blob audio:", err);
                        alert("Error downloading audio.");
                    });
            } else {
                // For direct URLs
                const link = document.createElement('a');
                link.href = audioSrc;
                link.download = filename; // The browser will try to use this name
                
                // For cross-origin downloads, this might not always work as expected
                // depending on server headers (Content-Disposition).
                // If `link.download` doesn't work for cross-origin, it will open in a new tab or download with server-provided name.
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            }
        });
    }


    // --- Text Area Character Count Logic ---
    if (textToSpeakElement && currentCharCountElement) {
        const updateCharCount = () => {
            const currentLength = textToSpeakElement.value.length;
            currentCharCountElement.textContent = currentLength;
        };
        updateCharCount();
        textToSpeakElement.addEventListener('input', updateCharCount);
    }


    // --- How to integrate with your existing TTS success logic ---
    // In your TTS success callback:
    /*
    // ...
    //showAlert('Audio generated successfully!', 'success');

    const audioPlayer = document.getElementById('audioPlayer');
    const customPlayerContainer = document.getElementById('customAudioPlayerContainer');
    const downloadBtn = document.getElementById('downloadBtn');

    audioPlayer.src = data.audio_url;
    audioPlayer.load(); // This will trigger 'loadedmetadata'

    // Reset UI elements
    if(playIcon) playIcon.style.display = 'block';
    if(pauseIcon) pauseIcon.style.display = 'none';
    if(seekBar) {
        seekBar.value = 0;
        updateSeekBarBackground(seekBar, 0);
    }
    if(currentTimeDisplay) currentTimeDisplay.textContent = formatTime(0);
    if(durationDisplay) durationDisplay.textContent = formatTime(0); // Will be updated by loadedmetadata

    customPlayerContainer.style.display = 'block';
    if (downloadBtn) downloadBtn.disabled = true; // Keep disabled until 'loadedmetadata' fires

    // audioPlayer.play(); // Optional autoplay
    // ...
    */

});