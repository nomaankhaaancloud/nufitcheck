import requests
import os
from dotenv import load_dotenv

load_dotenv()

# Set your ElevenLabs API Key here (or load from .env)
ELEVENLABS_API_KEY = os.getenv('ELEVENLABS_API_KEY')
AGENT_VOICE_ID = os.getenv('AGENT_VOICE_ID')

def generate_audio(text, voice_id=AGENT_VOICE_ID, api_key=ELEVENLABS_API_KEY, output_path="output.mp3"):
    """
    Generate audio from text using ElevenLabs API
    
    Args:
        text (str): Text to convert to speech
        voice_id (str): Voice ID to use
        api_key (str): ElevenLabs API key
        output_path (str): Path where to save the audio file
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Validate inputs
        if not text or not text.strip():
            print("Error: Empty text provided")
            return False
            
        if not api_key:
            print("Error: ElevenLabs API key not found")
            return False
            
        if not voice_id:
            print("Error: Voice ID not found")
            return False

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
        
        print(f"Generating audio for text: {text[:50]}...")
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        
        if response.status_code == 200:
            # Ensure directory exists
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            with open(output_path, "wb") as f:
                f.write(response.content)
            print(f"Audio saved to: {output_path}")
            return True
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return False
            
    except requests.exceptions.Timeout:
        print("Error: Request timed out")
        return False
    except requests.exceptions.RequestException as e:
        print(f"Error: Request failed - {e}")
        return False
    except Exception as e:
        print(f"Error: Unexpected error - {e}")
        return False

# Test function (commented out for production)
"""
if __name__ == "__main__":
    test_text = "Hello, this is a test of the voice generation system."
    test_output = "test_output.mp3"
    success = generate_audio(test_text, output_path=test_output)
    print(f"Test result: {'Success' if success else 'Failed'}")
"""