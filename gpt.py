import base64
import os
from typing import List, Dict, Optional
from dotenv import load_dotenv
from openai import OpenAI
from openai._exceptions import AuthenticationError, RateLimitError, OpenAIError

# Explicitly load .env file
load_dotenv()

# Debug: Print the API key (first few and last few characters for security)
api_key = os.getenv('OPENAI_API_KEY')
if api_key:
    print(f"API Key loaded: {api_key[:10]}...{api_key[-10:]}")
    # Create OpenAI client
    client = OpenAI(api_key=api_key)
else:
    print("API Key not found in environment variables")
    client = None

# Function to encode image to base64
def encode_image(image_path: str) -> str:
    """Encode image file to base64 string"""
    try:
        with open(image_path, "rb") as image_file:
            return base64.b64encode(image_file.read()).decode("utf-8")
    except Exception as e:
        print(f"Error encoding image {image_path}: {e}")
        return None

# Load and encode up to 5 images
def load_image_messages(folder_path: str, max_images: int = 5) -> List[Dict]:
    """Load and encode images from folder for GPT vision API"""
    image_messages = []
    image_extensions = (".jpg", ".jpeg", ".png")
    
    if not os.path.exists(folder_path):
        print(f"Folder path does not exist: {folder_path}")
        return image_messages
    
    try:
        files = sorted(os.listdir(folder_path))[:max_images]
        for filename in files:
            if filename.lower().endswith(image_extensions):
                image_path = os.path.join(folder_path, filename)
                base64_image = encode_image(image_path)
                
                if base64_image:
                    # Determine image type
                    if filename.lower().endswith('.png'):
                        image_type = 'png'
                    else:
                        image_type = 'jpeg'
                    
                    image_messages.append({
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/{image_type};base64,{base64_image}"
                        }
                    })
    except Exception as e:
        print(f"Error loading images from {folder_path}: {e}")
    
    return image_messages

# Send request to GPT-4o API using the new OpenAI client
def chat_with_gpt(messages: List[Dict], model: str = "gpt-4o", max_tokens: int = 300) -> Optional[str]:

    """Send messages to GPT API and return response"""
    if not client:
        print("OpenAI client not initialized - API key missing")
        return None
    try:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=1.2
        )
        
        return response.choices[0].message.content
        
    except AuthenticationError:
        print("Invalid API key. Please check your key.")
        return None
    except RateLimitError as e:
        print(f"Rate limit or billing error: {e}")
        return None
    except OpenAIError as e:
        print(f"OpenAI API error: {e}")
        return None
    except Exception as e:
        print(f"Error communicating with GPT: {e}")
        return None

def get_fashion_system_message() -> Dict:
    """Get the standard system message for fashion analysis"""
    return {
        "role": "system",
        "content": (
            "You are a Fashion Artist specialized in analyzing outfits from images. "
            "Your role is to give short, stylish feedback and outfit recommendations based on the visual appearance of the clothing. "
            "Assume the person's gender presentation based on visual cues. Rate outfit out of 100. "
            "Give feedback in one line and recommendations in two lines. "
            "You must always respond in 2-3 lines maximum, no matter the input."
            "Your task is to reply to to outfit analysis, image evaluation, or fashion recommendations"
            # "If the user asks anything unrelated to outfit analysis, image evaluation, or fashion recommendations, politely respond: "
            # "'I'm here to help only with fashion and outfit feedback based on the uploaded images. Let's stick to that!' "
            "If the user is done with chatting, then say to get feedback for another outfit please rescan it using the camera or upload it from the device."
        )
    }

def analyze_outfit_images(folder_path: str) -> Optional[str]:
    """Analyze outfit from images in folder - standalone function for testing"""
    image_messages = load_image_messages(folder_path)
    if not image_messages:
        return "No valid images found for analysis."
    
    messages = [
        get_fashion_system_message(),
        {"role": "user", "content": "Please analyze the following images."},
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": (
                        "Give outfit feedback and recommendations assuming the person's gender presentation based on visual cues. "
                        "Rate outfit out of 100. "
                        "While answering user queries, give answers in 2-3 lines only."
                    )
                }
            ] + image_messages
        }
    ]
    
    return chat_with_gpt(messages)  # Default model is now gpt-4o

def main():
    """Main function for testing - can be removed in production"""
    folder_path = "/home/ca/Downloads/NuFitCheck_test/extracted_frames"
    
    # Test image loading
    images = load_image_messages(folder_path)
    print(f"Loaded {len(images)} images")
    
    # Test outfit analysis
    result = analyze_outfit_images(folder_path)
    if result:
        print(f"Analysis result: {result}")
    else:
        print("Failed to get analysis")

if __name__ == "__main__":
    main()