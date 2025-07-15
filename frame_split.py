import cv2
import os
from pathlib import Path
import numpy as np

def extract_frames(video_path, output_dir, exclude_start=4, exclude_end=7):
    """
    Extract exactly 6 frames from the video:
    - 3 frames before `exclude_start` seconds (e.g., 0–4s)
    - 3 frames after `exclude_end` seconds (e.g., 7s–end)

    Args:
        video_path (str): Path to the input video file
        output_dir (str): Directory where extracted frames will be stored
        exclude_start (int): Start of exclusion range in seconds
        exclude_end (int): End of exclusion range in seconds

    Returns:
        str: Path to the extracted frame directory
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Subdirectory for frames
    video_name = Path(video_path).stem
    frames_subdir = output_path / f"{video_name}_frames"
    frames_subdir.mkdir(exist_ok=True)

    print(f"Storing frames in: {frames_subdir}")

    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        print(f"Error: Cannot open video file {video_path}")
        return

    fps = cap.get(cv2.CAP_PROP_FPS)
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    duration = total_frames / fps

    print(f"Video FPS: {fps}")
    print(f"Duration: {duration:.2f} seconds")

    # -------- Frame Sampling Strategy -------- #
    pre_range = (0, min(exclude_start, duration))
    post_range = (exclude_end, duration)

    def get_frame_timestamps(start, end, num_frames=3):
        if end - start < 1e-2:
            return []
        return np.linspace(start, end, num=num_frames, endpoint=False)

    # Timestamps (in seconds) to extract
    pre_timestamps = get_frame_timestamps(*pre_range, num_frames=3)
    post_timestamps = get_frame_timestamps(*post_range, num_frames=3)
    timestamps = list(pre_timestamps) + list(post_timestamps)

    # -------- Extract and Save Frames -------- #
    count = 0
    for i, sec in enumerate(timestamps, 1):
        frame_id = int(sec * fps)
        cap.set(cv2.CAP_PROP_POS_FRAMES, frame_id)
        success, frame = cap.read()
        if success:
            filename = frames_subdir / f"frame_{i:03d}.jpg"
            cv2.imwrite(str(filename), frame)
            count += 1
        else:
            print(f"Failed to extract frame at {sec:.2f}s")

    cap.release()
    print(f"Done. Extracted {count} frames to: {frames_subdir}")
    return str(frames_subdir)
