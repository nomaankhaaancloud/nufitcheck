import requests
import os
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