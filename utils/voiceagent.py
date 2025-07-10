import requests
import os
import base64
from dotenv import load_dotenv
import asyncio
import io
import logging

load_dotenv()

# Set your ElevenLabs API Key here (or load from .env)
ELEVENLABS_API_KEY = os.getenv('ELEVENLABS_API_KEY')
AGENT_VOICE_ID = os.getenv('AGENT_VOICE_ID')

# Configure logging
logger = logging.getLogger(__name__)

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

def speech_to_text_stream(audio_bytes, api_key=ELEVENLABS_API_KEY):
    """
    Convert speech to text using ElevenLabs Speech-to-Text API - optimized for streaming
    
    Args:
        audio_bytes: Audio file content as bytes
        api_key: ElevenLabs API key
    
    Returns:
        str: Transcribed text if successful, else None
    """
    try:
        if not audio_bytes or len(audio_bytes) < 1024:  # Minimum viable audio size
            logger.debug("Audio chunk too small or empty")
            return None

        if not api_key:
            logger.error("Missing API key")
            return None

        url = "https://api.elevenlabs.io/v1/speech-to-text"
        headers = {
            "xi-api-key": api_key
        }
        
        # Prepare the multipart form data
        files = {
            "file": ("audio_chunk.webm", audio_bytes, "audio/webm")
        }
        
        # Parameters optimized for real-time processing
        data = {
            "model_id": "scribe_v1",
            "response_format": "json"
        }

        # Shorter timeout for real-time processing
        response = requests.post(url, headers=headers, files=files, data=data, timeout=15)

        if response.status_code == 200:
            result = response.json()
            transcription = result.get("text", "").strip()
            
            # Filter out very short or meaningless transcriptions
            if len(transcription) < 3:
                return None
                
            return transcription
        else:
            logger.error(f"Speech-to-text streaming error: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        logger.error(f"Error in streaming speech-to-text: {e}")
        return None

async def generate_audio_stream(text, scan_id, voice_id=AGENT_VOICE_ID, api_key=ELEVENLABS_API_KEY):
    """
    Generate streaming audio response using ElevenLabs API
    
    Args:
        text: Text to convert to speech
        scan_id: Scan ID for context
        voice_id: ElevenLabs voice ID
        api_key: ElevenLabs API key
    
    Yields:
        dict: Audio chunks with metadata
    """
    try:
        if not text or not text.strip():
            logger.error("Empty text provided for audio generation")
            return

        if not api_key or not voice_id:
            logger.error("Missing API key or voice ID")
            return

        # Split text into smaller chunks for streaming
        text_chunks = split_text_for_streaming(text.strip())
        
        total_chunks = len(text_chunks)
        
        for chunk_index, text_chunk in enumerate(text_chunks):
            try:
                # Generate audio for this chunk
                audio_bytes = await generate_audio_chunk_async(text_chunk, voice_id, api_key)
                
                if audio_bytes:
                    # Convert to base64
                    audio_base64 = base64.b64encode(audio_bytes).decode('utf-8')
                    
                    yield {
                        "audio_base64": audio_base64,
                        "chunk_index": chunk_index,
                        "total_chunks": total_chunks,
                        "text_chunk": text_chunk,
                        "is_final": chunk_index == total_chunks - 1
                    }
                    
                    # Small delay between chunks for smoother streaming
                    await asyncio.sleep(0.1)
                else:
                    logger.error(f"Failed to generate audio for chunk {chunk_index}")
                    
            except Exception as e:
                logger.error(f"Error generating audio chunk {chunk_index}: {e}")
                continue
                
    except Exception as e:
        logger.error(f"Error in streaming audio generation: {e}")

def split_text_for_streaming(text, max_chunk_length=100):
    """
    Split text into smaller chunks for streaming audio generation
    
    Args:
        text: Text to split
        max_chunk_length: Maximum characters per chunk
    
    Returns:
        list: List of text chunks
    """
    if len(text) <= max_chunk_length:
        return [text]
    
    # Split by sentences first
    sentences = text.replace('!', '.').replace('?', '.').split('.')
    sentences = [s.strip() for s in sentences if s.strip()]
    
    chunks = []
    current_chunk = ""
    
    for sentence in sentences:
        if len(current_chunk) + len(sentence) + 1 <= max_chunk_length:
            current_chunk += sentence + ". "
        else:
            if current_chunk:
                chunks.append(current_chunk.strip())
            current_chunk = sentence + ". "
    
    if current_chunk:
        chunks.append(current_chunk.strip())
    
    return chunks

async def generate_audio_chunk_async(text, voice_id, api_key):
    """
    Generate audio for a single chunk asynchronously
    
    Args:
        text: Text to convert
        voice_id: ElevenLabs voice ID
        api_key: ElevenLabs API key
    
    Returns:
        bytes: Audio content if successful, else None
    """
    try:
        # Run the synchronous audio generation in a thread pool
        loop = asyncio.get_event_loop()
        audio_bytes = await loop.run_in_executor(
            None, 
            lambda: generate_audio_sync_optimized(text, voice_id, api_key)
        )
        return audio_bytes
    except Exception as e:
        logger.error(f"Error in async audio generation: {e}")
        return None

def generate_audio_sync_optimized(text, voice_id, api_key):
    """
    Optimized synchronous audio generation for streaming
    
    Args:
        text: Text to convert
        voice_id: ElevenLabs voice ID
        api_key: ElevenLabs API key
    
    Returns:
        bytes: Audio content if successful, else None
    """
    try:
        url = f"https://api.elevenlabs.io/v1/text-to-speech/{voice_id}/stream"
        headers = {
            "xi-api-key": api_key,
            "Content-Type": "application/json"
        }
        
        # Optimized settings for faster generation
        payload = {
            "text": text,
            "model_id": "eleven_turbo_v2",  # Faster model for real-time
            "voice_settings": {
                "stability": 0.4,  # Slightly less stable but faster
                "similarity_boost": 0.7,
                "style": 0.0,
                "use_speaker_boost": True
            },
            "output_format": "mp3_22050_32"  # Lower quality but faster
        }

        # Stream the response for faster delivery
        response = requests.post(
            url, 
            headers=headers, 
            json=payload, 
            timeout=10,  # Shorter timeout for real-time
            stream=True
        )

        if response.status_code == 200:
            # Collect all audio chunks
            audio_data = b""
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    audio_data += chunk
            return audio_data
        else:
            logger.error(f"Audio generation error: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        logger.error(f"Error in optimized audio generation: {e}")
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

# Real-time audio processing utilities
class AudioBuffer:
    """Buffer for collecting audio chunks in real-time"""
    
    def __init__(self, max_duration_seconds=30):
        self.buffer = io.BytesIO()
        self.max_size = max_duration_seconds * 16000 * 2  # Rough estimate for 16kHz 16-bit audio
        self.last_activity = None
    
    def add_chunk(self, audio_chunk):
        """Add audio chunk to buffer"""
        current_size = self.buffer.tell()
        
        if current_size + len(audio_chunk) > self.max_size:
            # Buffer full, reset
            self.reset()
        
        self.buffer.write(audio_chunk)
        import time
        self.last_activity = time.time()
    
    def get_audio(self):
        """Get all buffered audio"""
        position = self.buffer.tell()
        self.buffer.seek(0)
        audio_data = self.buffer.read()
        self.buffer.seek(position)
        return audio_data
    
    def reset(self):
        """Reset buffer"""
        self.buffer = io.BytesIO()
        self.last_activity = None
    
    def is_ready_for_processing(self, silence_threshold=1.0):
        """Check if buffer is ready for processing based on silence"""
        if not self.last_activity:
            return False
        
        import time
        return time.time() - self.last_activity > silence_threshold

def validate_audio_format(audio_bytes):
    """
    Validate audio format and return metadata
    
    Args:
        audio_bytes: Audio data as bytes
    
    Returns:
        dict: Audio metadata if valid, else None
    """
    try:
        if len(audio_bytes) < 44:  # Minimum WAV header size
            return None
        
        # Basic format detection
        if audio_bytes[:4] == b'RIFF' and audio_bytes[8:12] == b'WAVE':
            return {"format": "wav", "valid": True}
        elif audio_bytes[:3] == b'ID3' or audio_bytes[:2] == b'\xff\xfb':
            return {"format": "mp3", "valid": True}
        elif audio_bytes[:4] == b'OggS':
            return {"format": "ogg", "valid": True}
        elif audio_bytes[:4] == b'fLaC':
            return {"format": "flac", "valid": True}
        else:
            # Try to detect WebM/other formats
            return {"format": "unknown", "valid": True}
            
    except Exception as e:
        logger.error(f"Error validating audio format: {e}")
        return None
    


# Previous Code

# import requests
# import os
# import base64
# from dotenv import load_dotenv

# load_dotenv()

# # Set your ElevenLabs API Key here (or load from .env)
# ELEVENLABS_API_KEY = os.getenv('ELEVENLABS_API_KEY')
# AGENT_VOICE_ID = os.getenv('AGENT_VOICE_ID')

# def generate_audio(text, voice_id=AGENT_VOICE_ID, api_key=ELEVENLABS_API_KEY):
#     """
#     Generate audio from text using ElevenLabs API and return bytes
    
#     Returns:
#         bytes: Audio content in bytes if successful, else None
#     """
#     try:
#         if not text or not text.strip():
#             print("Error: Empty text provided")
#             return None

#         if not api_key or not voice_id:
#             print("Error: Missing API key or voice ID")
#             return None

#         url = f"https://api.elevenlabs.io/v1/text-to-speech/{voice_id}"
#         headers = {
#             "xi-api-key": api_key,
#             "Content-Type": "application/json"
#         }
#         payload = {
#             "text": text.strip(),
#             "model_id": "eleven_monolingual_v1",
#             "voice_settings": {
#                 "stability": 0.5,
#                 "similarity_boost": 0.75
#             }
#         }

#         response = requests.post(url, headers=headers, json=payload, timeout=30)

#         if response.status_code == 200:
#             return response.content
#         else:
#             print(f"Error: {response.status_code} - {response.text}")
#             return None
#     except Exception as e:
#         print(f"Error generating audio: {e}")
#         return None

# def speech_to_text(audio_bytes, api_key=ELEVENLABS_API_KEY):
#     """
#     Convert speech to text using ElevenLabs Speech-to-Text API
    
#     Args:
#         audio_bytes: Audio file content as bytes
#         api_key: ElevenLabs API key
    
#     Returns:
#         str: Transcribed text if successful, else None
#     """
#     try:
#         if not audio_bytes:
#             print("Error: No audio data provided")
#             return None

#         if not api_key:
#             print("Error: Missing API key")
#             return None

#         url = "https://api.elevenlabs.io/v1/speech-to-text"
#         headers = {
#             "xi-api-key": api_key
#         }
        
#         # Prepare the multipart form data
#         files = {
#             "file": ("audio.mp3", audio_bytes, "audio/mpeg")
#         }
        
#         # Optional parameters - you can adjust these as needed
#         data = {
#             "model_id": "scribe_v1"
#         }

#         response = requests.post(url, headers=headers, files=files, data=data, timeout=30)

#         if response.status_code == 200:
#             result = response.json()
#             return result.get("text", "").strip()
#         else:
#             print(f"Speech-to-text error: {response.status_code} - {response.text}")
#             return None
            
#     except Exception as e:
#         print(f"Error in speech-to-text: {e}")
#         return None

# def generate_response_audio_base64(text, scan_id, context="chat", voice_id=AGENT_VOICE_ID, api_key=ELEVENLABS_API_KEY):
#     """
#     Generate audio response and return as base64 encoded string
    
#     Args:
#         text: Text to convert to speech
#         scan_id: Scan ID for filename
#         context: Context for filename (e.g., "chat", "analysis")
#         voice_id: ElevenLabs voice ID
#         api_key: ElevenLabs API key
    
#     Returns:
#         dict: Contains audio_base64, audio_format, and filename if successful, else None
#     """
#     try:
#         # Generate audio using existing function
#         audio_bytes = generate_audio(text, voice_id, api_key)
        
#         if not audio_bytes:
#             return None
            
#         # Convert to base64
#         audio_base64 = base64.b64encode(audio_bytes).decode('utf-8')
        
#         # Create filename
#         filename = f"response_{scan_id}_{context}.mp3"
        
#         return {
#             "audio_base64": audio_base64,
#             "audio_format": "mp3",
#             "filename": filename
#         }
        
#     except Exception as e:
#         print(f"Error generating base64 audio: {e}")
#         return None