import cv2
import numpy as np


class BiometricDetector:
    def __init__(self):
        """Initialize OpenCV classifiers and detector parameters."""
        self.face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        )

    def check_liveness(self, frame):
        """
        Processes a video frame to detect face presence.
        Returns face_detected status and bounding box coordinates.
        """
        if frame is None or frame.size == 0:
            return {
                "face_detected": False,
                "box": None
            }

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = self.face_cascade.detectMultiScale(gray, 1.1, 4)

        for (x, y, w, h) in faces:
            return {
                "face_detected": True,
                "box": [int(x), int(y), int(w), int(h)]
            }

        return {
            "face_detected": False,
            "box": None
        }
