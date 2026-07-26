import cv2
import numpy as np


class ScreenshotPreprocessor:

    def __init__(self, max_width=1280, max_height=720):
        self.max_width = max_width
        self.max_height = max_height

    def resize(self, image):

        h, w = image.shape[:2]

        if w <= self.max_width and h <= self.max_height:
            return image

        scale = min(self.max_width / w,
                    self.max_height / h)

        new_w = int(w * scale)
        new_h = int(h * scale)

        return cv2.resize(image, (new_w, new_h))

    def enhance(self, image):

        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

        gray = cv2.GaussianBlur(gray, (3, 3), 0)

        gray = cv2.equalizeHist(gray)

        return gray

    def preprocess(self, img_bytes):

        image_array = np.frombuffer(img_bytes, np.uint8)

        image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)

        if image is None:
            raise ValueError("Invalid image.")

        image = self.resize(image)

        enhanced = self.enhance(image)

        return {
            "original": image,
            "processed": enhanced,
            "height": image.shape[0],
            "width": image.shape[1]
        }


if __name__ == "__main__":

    print("Screenshot Preprocessor Ready")