import os
import uuid
import logging
import numpy as np
from PIL import Image, ImageDraw
from flask import request, jsonify, current_app as app, send_from_directory
from flask_restful import Resource

from werkzeug.utils import secure_filename
# from pydub import AudioSegment # Only necessary if you directly use pydub for raw audio manipulation

# Corrected MoviePy import line:
# All commonly used classes are often aliased directly under the 'moviepy' top-level package.
from moviepy import AudioFileClip, ColorClip, TextClip, CompositeVideoClip, ImageClip, VideoClip 

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ... (rest of your code remains the same as the last provided version) ...
# Configuration
ALLOWED_AUDIO_EXTENSIONS = {'wav', 'mp3', 'webm', 'ogg', 'aac'}
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Define the path to your font file
font_file_path = os.path.join(os.path.dirname(__file__), 'fonts', 'Inter-Regular.ttf')

# Ensure the fonts directory exists
if not os.path.exists(os.path.dirname(font_file_path)):
    os.makedirs(os.path.dirname(font_file_path), exist_ok=True)
    logging.info(f"Created font directory: {os.path.dirname(font_file_path)}")

def allowed_file(filename, allowed_extensions):
    """Checks if a filename has an allowed extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

def validate_color(color_hex):
    """Validates if a string is a valid hex color code."""
    if not isinstance(color_hex, str):
        return False
    if color_hex.startswith('#'):
        hex_value = color_hex[1:]
    else:
        hex_value = color_hex # Allow hex without # for internal use
    return len(hex_value) in (3, 6) and all(c in '0123456789abcdefABCDEF' for c in hex_value.lower())

def validate_float_range(value, min_val, max_val):
    """Validates if a value is a float within a specified range."""
    try:
        f_val = float(value)
        return min_val <= f_val <= max_val
    except (ValueError, TypeError):
        return False

# --- Conceptual Waveform Drawing Function ---
def draw_waveform_frame(t, audio_duration, waveform_style, waveform_color, video_width, video_height):
    """
    Conceptual function to draw a waveform-like animation frame.
    This does NOT use actual audio data.
    To generate a real audio waveform, you would need to:
    1. Load the *raw audio samples* (e.g., using `pydub` or `soundfile`) outside this function,
       and pass the NumPy array of samples into this function.
    2. Inside this function, extract the relevant audio segment for time `t`.
    3. Perform signal processing (e.g., RMS for amplitude, FFT for frequency bars).
    4. Use `matplotlib.pyplot` or `Pillow.ImageDraw` to render the actual waveform based on audio data.
    5. Convert the rendered image/plot to a NumPy array for MoviePy.
    """
    # logging.debug(f"draw_waveform_frame called at t={t:.2f}") # Uncomment for debugging

    frame = np.zeros((video_height, video_width, 3), dtype=np.uint8) # Start with a black frame
    
    # Convert waveform_color hex to RGB tuple
    hex_val = waveform_color.lstrip('#')
    try:
        rgb = tuple(int(hex_val[i:i+2], 16) for i in (0, 2, 4))
    except ValueError:
        logging.warning(f"Invalid waveform_color format: {waveform_color}. Defaulting to white.")
        rgb = (255, 255, 255) # Default to white on error

    img = Image.fromarray(frame)
    draw = ImageDraw.Draw(img)

    # Simplified animation based on time 't'
    progress = t / audio_duration if audio_duration > 0 else 0
    
    if waveform_style == 'bars':
        num_bars = 40 
        bar_spacing = video_width / num_bars
        for i in range(num_bars):
            amplitude_factor = 0.5 + 0.5 * np.sin(t * 5 + i * 0.5)
            bar_height = int(video_height * 0.6 * amplitude_factor) # Increased height
            
            x0 = int(i * bar_spacing)
            x1 = int(x0 + bar_spacing * 0.8)
            y0 = video_height // 2 - bar_height // 2
            y1 = video_height // 2 + bar_height // 2
            draw.rectangle([(x0, y0), (x1, y1)], fill=rgb)

    elif waveform_style == 'lines' or waveform_style == 'smooth-lines':
        points = []
        line_amplitude = video_height * 0.2 # Increased amplitude
        for x in range(0, video_width, 10):
            y = int(video_height // 2 + line_amplitude * np.sin(t * 3 + x * 0.05))
            points.append((x, y))
        draw.line(points, fill=rgb, width=5) # Increased width
    
    elif waveform_style == 'circles':
        max_radius = min(video_width, video_height) // 3 # Larger circles
        current_radius = int(max_radius * (1 + np.sin(t * 2)) / 2)
        
        x_center, y_center = video_width // 2, video_height // 2
        for r_step in range(0, max_radius + 1, max_radius // 5): # Iterate in steps
            r = r_step + current_radius % (max_radius // 5) # Create a pulsing effect
            if r > 0 and r <= max_radius:
                draw.ellipse([x_center - r, y_center - r, x_center + r, y_center + r], outline=rgb, width=3)
    
    elif waveform_style == 'frequency-bars':
        num_freq_bands = 20
        band_width = video_width / num_freq_bands
        for i in range(num_freq_bands):
            amplitude_factor = 0.2 + 0.8 * np.cos(t * 4 + i * 0.2)**2
            bar_height = int(video_height * 0.6 * amplitude_factor) # Increased height
            
            x0 = int(i * band_width)
            x1 = int(x0 + band_width * 0.8)
            y0 = video_height - bar_height # Bars rise from bottom
            y1 = video_height
            draw.rectangle([(x0, y0), (x1, y1)], fill=rgb)

    return np.array(img)


class PodcastGenerate(Resource):
    def post(self):
        UPLOAD_FOLDER = os.path.join(app.root_path, 'static', app.config['UPLOAD_FOLDER'])    
        logging.info("Received request for podcast generation.")

        # Validate audio file
        if 'audio' not in request.files:
            logging.warning("No audio file part in request.")
            return jsonify({'message': 'No audio file provided'}), 400
        audio_file = request.files['audio']
        if audio_file.filename == '':
            logging.warning("No selected audio file.")
            return jsonify({'message': 'No selected audio file'}), 400
        if not allowed_file(audio_file.filename, ALLOWED_AUDIO_EXTENSIONS):
            logging.warning(f"Audio file extension not allowed: {audio_file.filename}")
            return jsonify({'message': 'Audio file type not allowed'}), 400

        # Sanitize and save audio file
        audio_filename = secure_filename(audio_file.filename)
        unique_audio_filename = f"{uuid.uuid4()}_{audio_filename}"
        audio_filepath = os.path.join(UPLOAD_FOLDER, unique_audio_filename)
        try:
            audio_file.save(audio_filepath)
            logging.info(f"Audio file saved to: {audio_filepath}")
        except Exception as e:
            logging.error(f"Failed to save audio file: {e}")
            return jsonify({'message': f'Failed to save audio file: {str(e)}'}), 500

        # Extract and validate other parameters
        waveform_style = request.form.get('waveformStyle', 'bars') # Default for safety
        waveform_color = request.form.get('waveformColor', '#FFFFFF') # Default for safety
        background_color_hex = request.form.get('backgroundColor', '#000000') # Default for safety
        background_opacity_str = request.form.get('backgroundOpacity', '1.0') # Default for safety
        playback_speed_str = request.form.get('playbackSpeed', '1.0') # Default for safety
        text_overlay = request.form.get('textOverlay', '')
        audio_output_format = request.form.get('downloadFormat', 'mp3').lower() 

        # Basic validation for other fields
        if waveform_style not in ['bars', 'lines', 'circles', 'frequency-bars', 'smooth-lines']:
            logging.warning(f"Invalid waveform style: {waveform_style}")
            return jsonify({'message': 'Invalid waveform style'}), 400
        if not validate_color(waveform_color):
            logging.warning(f"Invalid waveform color: {waveform_color}")
            return jsonify({'message': 'Invalid waveform color format'}), 400
        if not validate_color(background_color_hex):
            logging.warning(f"Invalid background color: {background_color_hex}")
            return jsonify({'message': 'Invalid background color format'}), 400
        if not validate_float_range(background_opacity_str, 0.0, 1.0):
            logging.warning(f"Invalid background opacity: {background_opacity_str}")
            return jsonify({'message': 'Invalid background opacity value (must be between 0 and 1)'}), 400
        if not validate_float_range(playback_speed_str, 0.1, 5.0): # Assuming reasonable speed range
            logging.warning(f"Invalid playback speed: {playback_speed_str}")
            return jsonify({'message': 'Invalid playback speed value'}), 400
        if audio_output_format not in ['webm', 'wav', 'mp3']:
            logging.warning(f"Invalid audio output format for video: {audio_output_format}")
            return jsonify({'message': 'Invalid audio output format for video'}), 400

        background_opacity = float(background_opacity_str)
        playback_speed = float(playback_speed_str)

        # Handle background image
        background_image_file = request.files.get('backgroundImage')
        background_image_filepath = None
        if background_image_file and background_image_file.filename != '':
            if not allowed_file(background_image_file.filename, ALLOWED_IMAGE_EXTENSIONS):
                logging.warning(f"Background image extension not allowed: {background_image_file.filename}")
                return jsonify({'message': 'Background image file type not allowed'}), 400
            bg_image_filename = secure_filename(background_image_file.filename)
            unique_bg_image_filename = f"{uuid.uuid4()}_{bg_image_filename}"
            background_image_filepath = os.path.join(UPLOAD_FOLDER, unique_bg_image_filename)
            try:
                background_image_file.save(background_image_filepath)
                logging.info(f"Background image saved to: {background_image_filepath}")
            except Exception as e:
                logging.error(f"Failed to save background image: {e}")
                return jsonify({'message': f'Failed to save background image: {str(e)}'}), 500

        output_video_filename = f"waveform_video_{uuid.uuid4()}.mp4" # Always output MP4 video
        output_video_filepath = os.path.join(UPLOAD_FOLDER, output_video_filename)

        try:
           # 1. Load the audio clip
            audio_clip = AudioFileClip(audio_filepath)
            audio_clip = audio_clip.with_fps(44100) # Ensure consistent audio FPS

            # Apply playback speed to audio clip
            if playback_speed != 1.0:
                audio_clip = audio_clip.speedx(playback_speed)

            # 2. Create the background video clip
            video_width, video_height = 1280, 720 # Standard video dimensions
            
            if background_image_filepath:
                background_clip = ImageClip(background_image_filepath).with_duration(audio_clip.duration)
                background_clip = background_clip.resized(width=video_width, height=video_height)
            else:
                hex_value = background_color_hex.lstrip('#')
                rgb_color = tuple(int(hex_value[i:i+2], 16) for i in (0, 2, 4))
                
                background_clip = ColorClip(size=(video_width, video_height), 
                                            color=rgb_color, 
                                            duration=audio_clip.duration)

            # Initialize a list of clips to composite. Background is always the base layer.
            composite_clips = [background_clip]

            # 3. Create the text overlay clip
            if text_overlay:
                if not os.path.exists(font_file_path):
                    logging.warning(f"Font file not found at: {font_file_path}. Text overlay will be skipped.")
                else:
                    try:
                        text_clip = TextClip(font=font_file_path,
                                            text=text_overlay,
                                            font_size=50,
                                            color='white',
                                            stroke_color='black',
                                            stroke_width=1,
                                            bg_color='transparent'
                                            )
                        text_clip = text_clip.with_position(('center', 0.05), relative=True).with_duration(audio_clip.duration)
                        composite_clips.append(text_clip)
                    except Exception as e:
                        logging.error(f"Failed to create TextClip with font {font_file_path}: {e}", exc_info=True)
            
            # 4. Create and add Waveform clip (Conceptual/Placeholder Implementation)
            try:
                waveform_video_clip = VideoClip(make_frame=lambda t: draw_waveform_frame(t, audio_clip.duration, waveform_style, waveform_color, video_width, video_height),
                                                duration=audio_clip.duration,
                                                fps=24)
                
                waveform_video_clip = waveform_video_clip.with_position(('center', 0.9), relative=True)
                composite_clips.append(waveform_video_clip)

            except Exception as e:
                logging.error(f"Failed to create waveform clip: {e}", exc_info=True)

            # Final Composite Video Clip (order matters for layers, earlier in list is lower layer)
            final_video_clip = CompositeVideoClip(composite_clips, size=(video_width, video_height))

            # 5. Set the audio of the final video clip
            final_video_clip = final_video_clip.with_audio(audio_clip)

            # 6. Write the final video file
            final_video_clip.write_videofile(output_video_filepath, fps=24, codec='libx264', audio_codec='aac')
            logging.info(f"Video generated successfully: {output_video_filepath}")
            
            # Construct the URL for download
            video_url = f"/api/v2/podcast/download/{os.path.basename(output_video_filepath)}"
            logging.info(f"Generated video download URL: {video_url}")

            return jsonify({'message': 'Video generation simulated successfully', 'video_url': video_url}), 200

        except Exception as e:
            logging.error(f"Error during video generation: {e}", exc_info=True)
            return jsonify({'message': f'Video generation failed: {str(e)}. Ensure FFmpeg is installed and accessible in your system\'s PATH.'}), 500
        finally:
            # Clean up uploaded files
            if os.path.exists(audio_filepath):
                os.remove(audio_filepath)
                logging.info(f"Cleaned up uploaded audio: {audio_filepath}")
            if background_image_filepath and os.path.exists(background_image_filepath):
                os.remove(background_image_filepath)
                logging.info(f"Cleaned up uploaded background image: {background_image_filepath}")

class DownloadFile(Resource):
    def get(self, filename):
        UPLOAD_FOLDER = os.path.join(app.root_path, 'static', app.config['UPLOAD_FOLDER']) 
        logging.info(f"Received download request for: {filename}")
        try:
            return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)
        except FileNotFoundError:
            logging.warning(f"File not found for download: {filename}")
            return jsonify({'message': 'File not found'}), 404
        except Exception as e:
            logging.error(f"Error serving file {filename} for download: {e}", exc_info=True)
            return jsonify({'message': f'Error serving file: {str(e)}'}), 500