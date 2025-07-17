import openai
import os
import base64
from dotenv import load_dotenv
import asyncio
import io
import logging
from typing import AsyncGenerator, Dict, Optional
import json

load_dotenv()

# Set your OpenAI API Key here (or load from .env)
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
openai.api_key = OPENAI_API_KEY

# Configure logging
logger = logging.getLogger(__name__)

class OpenAITTSStreamer:
    """OpenAI TTS Streaming client"""
    
    def __init__(self, api_key: str = None, model: str = "tts-1", voice: str = "shimmer"):
        """
        Initialize OpenAI TTS Streamer
        
        Args:
            api_key: OpenAI API key
            model: TTS model (tts-1 or tts-1-hd)
            voice: Voice to use (alloy, echo, fable, onyx, nova, shimmer)
        """
        self.client = openai.OpenAI(api_key=api_key or OPENAI_API_KEY)
        self.model = model
        self.voice = voice
    
    async def generate_audio_stream(self, text: str, scan_id: str) -> AsyncGenerator[Dict, None]:
        """
        Generate streaming audio response using OpenAI TTS API
        
        Args:
            text: Text to convert to speech
            scan_id: Scan ID for context
        
        Yields:
            dict: Audio chunks with metadata
        """
        try:
            if not text or not text.strip():
                logger.error("Empty text provided for audio generation")
                return

            # Split text into smaller chunks for streaming
            text_chunks = self._split_text_for_streaming(text.strip())
            total_chunks = len(text_chunks)
            
            for chunk_index, text_chunk in enumerate(text_chunks):
                try:
                    # Generate complete audio for this chunk
                    audio_content = await self._generate_chunk_audio(text_chunk)
                    
                    if audio_content:
                        # Convert to base64
                        audio_base64 = base64.b64encode(audio_content).decode('utf-8')
                        
                        # Yield the complete audio chunk once
                        yield {
                            "audio_base64": audio_base64,
                            "chunk_index": chunk_index,
                            "total_chunks": total_chunks,
                            "text_chunk": text_chunk,
                            "is_final": chunk_index == total_chunks - 1,
                            "scan_id": scan_id
                        }
                        
                        # Small delay between chunks for smoother streaming
                        await asyncio.sleep(0.1)
                        
                except Exception as e:
                    logger.error(f"Error generating audio chunk {chunk_index}: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error in streaming audio generation: {e}")
    
    async def _generate_chunk_audio(self, text: str) -> Optional[bytes]:
        """
        Generate complete audio for a single text chunk
        
        Args:
            text: Text to convert to speech
        
        Returns:
            bytes: Complete audio data for the chunk
        """
        try:
            # Run the OpenAI TTS call in a thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            
            def _sync_generate():
                response = self.client.audio.speech.create(
                    model=self.model,
                    voice=self.voice,
                    input=text,
                    response_format="mp3"
                )
                return response.content
            
            # Execute in thread pool and return complete audio
            audio_content = await loop.run_in_executor(None, _sync_generate)
            return audio_content
                
        except Exception as e:
            logger.error(f"Error in OpenAI TTS generation: {e}")
            return None
    
    def _split_text_for_streaming(self, text: str, max_chunk_length: int = 300) -> list:
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
    
    def generate_audio_sync(self, text: str) -> Optional[bytes]:
        """
        Generate audio synchronously (for backward compatibility)
        
        Args:
            text: Text to convert to speech
        
        Returns:
            bytes: Audio content if successful, else None
        """
        try:
            if not text or not text.strip():
                logger.error("Empty text provided")
                return None
                
            response = self.client.audio.speech.create(
                model=self.model,
                voice=self.voice,
                input=text.strip(),
                response_format="mp3"
            )
            
            return response.content
            
        except Exception as e:
            logger.error(f"Error generating audio: {e}")
            return None

# Initialize global TTS streamer
tts_streamer = OpenAITTSStreamer()

def generate_audio(text: str, voice_id: str = None, api_key: str = None) -> Optional[bytes]:
    """
    Generate audio from text using OpenAI TTS API (backward compatibility)
    
    Args:
        text: Text to convert to speech
        voice_id: Voice ID (mapped to OpenAI voice names)
        api_key: API key (not used for OpenAI, kept for compatibility)
    
    Returns:
        bytes: Audio content in bytes if successful, else None
    """
    # Map voice_id to OpenAI voice names if needed
    voice_map = {
        "default": "shimmer",
        "female": "shimmer",
        "male": "onyx",
        "shimmer": "shimmer",
        "alloy": "alloy",
        "echo": "echo",
        "fable": "fable"
    }
    
    voice = voice_map.get(voice_id, "shimmer")
    streamer = OpenAITTSStreamer(voice=voice)
    
    return streamer.generate_audio_sync(text)

def speech_to_text(audio_bytes: bytes, api_key: str = OPENAI_API_KEY) -> Optional[str]:
    """
    Convert speech to text using OpenAI Whisper API
    
    Args:
        audio_bytes: Audio file content as bytes
        api_key: OpenAI API key
    
    Returns:
        str: Transcribed text if successful, else None
    """
    try:
        if not audio_bytes:
            logger.error("No audio data provided")
            return None

        if not api_key:
            logger.error("Missing API key")
            return None

        client = openai.OpenAI(api_key=api_key)
        
        # Create a file-like object from bytes
        audio_file = io.BytesIO(audio_bytes)
        audio_file.name = "audio.mp3"  # Required for OpenAI API
        
        # Use Whisper API for transcription
        response = client.audio.transcriptions.create(
            model="whisper-1",
            file=audio_file,
            response_format="text"
        )
        
        return response.strip() if response else None
        
    except Exception as e:
        logger.error(f"Error in speech-to-text: {e}")
        return None

def speech_to_text_stream(audio_bytes: bytes, api_key: str = OPENAI_API_KEY) -> Optional[str]:
    """
    Convert speech to text using OpenAI Whisper API - optimized for streaming
    
    Args:
        audio_bytes: Audio file content as bytes
        api_key: OpenAI API key
    
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

        client = openai.OpenAI(api_key=api_key)
        
        # Create a file-like object from bytes
        audio_file = io.BytesIO(audio_bytes)
        audio_file.name = "audio_chunk.webm"
        
        # Use Whisper API for transcription
        response = client.audio.transcriptions.create(
            model="whisper-1",
            file=audio_file,
            response_format="text"
        )
        
        transcription = response.strip() if response else ""
        
        # Filter out very short or meaningless transcriptions
        if len(transcription) < 3:
            return None
            
        return transcription
        
    except Exception as e:
        logger.error(f"Error in streaming speech-to-text: {e}")
        return None

async def generate_audio_stream(text: str, scan_id: str, voice_id: str = None, api_key: str = None) -> AsyncGenerator[Dict, None]:
    """
    Generate streaming audio response using OpenAI TTS API
    
    Args:
        text: Text to convert to speech
        scan_id: Scan ID for context
        voice_id: Voice ID (mapped to OpenAI voice names)
        api_key: API key (not used for OpenAI, kept for compatibility)
    
    Yields:
        dict: Audio chunks with metadata
    """
    # Map voice_id to OpenAI voice names if needed
    voice_map = {
        "default": "shimmer",
        "female": "shimmer",
        "male": "onyx",
        "shimmer": "shimmer",
        "alloy": "alloy",
        "echo": "echo",
        "fable": "fable"
    }
    
    voice = voice_map.get(voice_id, "shimmer")
    streamer = OpenAITTSStreamer(voice=voice)
    
    async for chunk in streamer.generate_audio_stream(text, scan_id):
        yield chunk

def generate_response_audio_base64(text: str, scan_id: str, context: str = "chat", voice_id: str = None, api_key: str = None) -> Optional[Dict]:
    """
    Generate audio response and return as base64 encoded string
    
    Args:
        text: Text to convert to speech
        scan_id: Scan ID for filename
        context: Context for filename (e.g., "chat", "analysis")
        voice_id: Voice ID (mapped to OpenAI voice names)
        api_key: API key (not used for OpenAI, kept for compatibility)
    
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
        logger.error(f"Error generating base64 audio: {e}")
        return None

# Real-time audio processing utilities (kept from original)
class AudioBuffer:
    """Buffer for collecting audio chunks in real-time"""
    
    def __init__(self, max_duration_seconds: int = 30):
        self.buffer = io.BytesIO()
        self.max_size = max_duration_seconds * 16000 * 2  # Rough estimate for 16kHz 16-bit audio
        self.last_activity = None
    
    def add_chunk(self, audio_chunk: bytes):
        """Add audio chunk to buffer"""
        current_size = self.buffer.tell()
        
        if current_size + len(audio_chunk) > self.max_size:
            # Buffer full, reset
            self.reset()
        
        self.buffer.write(audio_chunk)
        import time
        self.last_activity = time.time()
    
    def get_audio(self) -> bytes:
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
    
    def is_ready_for_processing(self, silence_threshold: float = 1.0) -> bool:
        """Check if buffer is ready for processing based on silence"""
        if not self.last_activity:
            return False
        
        import time
        return time.time() - self.last_activity > silence_threshold

def validate_audio_format(audio_bytes: bytes) -> Optional[Dict]:
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