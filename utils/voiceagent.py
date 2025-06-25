import requests
import os
import base64
from dotenv import load_dotenv

load_dotenv()

# Set your ElevenLabs API Key here (or load from .env)
ELEVENLABS_API_KEY = os.getenv('ELEVENLABS_API_KEY')
AGENT_VOICE_ID = os.getenv('AGENT_VOICE_ID')

def generate_audio(text, voice_id=AGENT_VOICE_ID, api_key=ELEVENLABS_API_KEY):
    """
    Generate audio from text using ElevenLabs API and return bytes
    
    Returns:
        bytes: Audio content in bytes if successful, else None
    """
    try:
        if not text or not text.strip():
            print("Error: Empty text provided")
            return None

        if not api_key or not voice_id:
            print("Error: Missing API key or voice ID")
            return None

        url = f"https://api.elevenlabs.io/v1/text-to-speech/{voice_id}"
        headers = {
            "xi-api-key": api_key,
            "Content-Type": "application/json"
        }
        payload = {
            "text": text.strip(),
            "model_id": "eleven_monolingual_v1",
            "voice_settings": {
                "stability": 0.5,
                "similarity_boost": 0.75
            }
        }

        response = requests.post(url, headers=headers, json=payload, timeout=30)

        if response.status_code == 200:
            return response.content
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Error generating audio: {e}")
        return None

def speech_to_text(audio_bytes, api_key=ELEVENLABS_API_KEY):
    """
    Convert speech to text using ElevenLabs Speech-to-Text API
    
    Args:
        audio_bytes: Audio file content as bytes
        api_key: ElevenLabs API key
    
    Returns:
        str: Transcribed text if successful, else None
    """
    try:
        if not audio_bytes:
            print("Error: No audio data provided")
            return None

        if not api_key:
            print("Error: Missing API key")
            return None

        url = "https://api.elevenlabs.io/v1/speech-to-text"
        headers = {
            "xi-api-key": api_key
        }
        
        # Prepare the multipart form data
        files = {
            "file": ("audio.mp3", audio_bytes, "audio/mpeg")
        }
        
        # Optional parameters - you can adjust these as needed
        data = {
            "model_id": "scribe_v1"
        }

        response = requests.post(url, headers=headers, files=files, data=data, timeout=30)

        if response.status_code == 200:
            result = response.json()
            return result.get("text", "").strip()
        else:
            print(f"Speech-to-text error: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        print(f"Error in speech-to-text: {e}")
        return None

def generate_response_audio_base64(text, scan_id, context="chat", voice_id=AGENT_VOICE_ID, api_key=ELEVENLABS_API_KEY):
    """
    Generate audio response and return as base64 encoded string
    
    Args:
        text: Text to convert to speech
        scan_id: Scan ID for filename
        context: Context for filename (e.g., "chat", "analysis")
        voice_id: ElevenLabs voice ID
        api_key: ElevenLabs API key
    
    Returns:
        dict: Contains audio_base64, audio_format, and filename if successful, else None
    """
    try:
        # Generate audio using existing function
        audio_bytes = generate_audio(text, voice_id, api_key)
        
        if not audio_bytes:
            return None
            
        # Convert to base64
        audio_base64 = base64.b64encode(audio_bytes).decode('utf-8')
        
        # Create filename
        filename = f"response_{scan_id}_{context}.mp3"
        
        return {
            "audio_base64": audio_base64,
            "audio_format": "mp3",
            "filename": filename
        }
        
    except Exception as e:
        print(f"Error generating base64 audio: {e}")
        return None