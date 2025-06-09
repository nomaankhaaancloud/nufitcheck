import cv2
import os
from pathlib import Path

def extract_frames(video_path, output_dir):
    # Create output directory if it doesn't exist
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Open the video file
    cap = cv2.VideoCapture(video_path)
    
    if not cap.isOpened():
        print(f"Error: Cannot open video file {video_path}")
        return

    fps = cap.get(cv2.CAP_PROP_FPS)
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    duration_seconds = int(total_frames / fps)

    print(f"Video FPS: {fps}")
    print(f"Total Duration: {duration_seconds} seconds")
    
    count = 0

    for sec in range(duration_seconds):
        frame_id = int(sec * fps)
        cap.set(cv2.CAP_PROP_POS_FRAMES, frame_id)
        success, frame = cap.read()
        if success:
            output_filename = os.path.join(output_dir, f"frame_{sec:04d}.jpg")
            cv2.imwrite(output_filename, frame)
            count += 1
        else:
            print(f"Warning: Could not read frame at {sec} seconds")

    cap.release()
    print(f"Extraction complete. {count} frames saved to '{output_dir}'.")

if __name__ == "__main__":
    # Example usage
    video_file = '/home/ca/Downloads/NuFitCheck_test/videoplayback.mp4'
    output_folder = 'extracted_frames'
    extract_frames(video_file, output_folder)

