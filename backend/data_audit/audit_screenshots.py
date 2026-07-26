import os
import cv2
import numpy as np
from collections import Counter

# ============================================================
# Project Paths
# ============================================================

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

SCREENSHOT_DATASET_PATH = os.path.join(
    BASE_DIR,
    "datasets",
    "raw",
    "screenshots"
)

REPORT_PATH = os.path.join(
    BASE_DIR,
    "datasets",
    "reports"
)

os.makedirs(REPORT_PATH, exist_ok=True)

VALID_EXTENSIONS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".bmp",
    ".webp"
)

# ============================================================
# Find all screenshots
# ============================================================

def find_images():

    image_files = []

    for folder in os.listdir(SCREENSHOT_DATASET_PATH):

        folder_path = os.path.join(SCREENSHOT_DATASET_PATH, folder)

        if os.path.isdir(folder_path):

            for file in os.listdir(folder_path):

                if file.lower().endswith(VALID_EXTENSIONS):

                    image_files.append(
                        (
                            os.path.join(folder_path, file),
                            folder
                        )
                    )

    return image_files


# ============================================================
# Dataset Statistics
# ============================================================

def dataset_statistics(images):

    stats = {}

    widths = []
    heights = []
    brightness = []

    corrupted = 0
    formats = Counter()
    labels = Counter()

    for image_path, label in images:

        labels[label] += 1

        formats[
            os.path.splitext(image_path)[1].lower()
        ] += 1

        img = cv2.imread(image_path)

        if img is None:

            corrupted += 1
            continue

        h, w = img.shape[:2]

        widths.append(w)
        heights.append(h)

        gray = cv2.cvtColor(
            img,
            cv2.COLOR_BGR2GRAY
        )

        brightness.append(gray.mean())

    stats["Total Images"] = len(images)
    stats["Corrupted Images"] = corrupted

    stats["Average Width"] = (
        round(np.mean(widths), 2)
        if widths else 0
    )

    stats["Average Height"] = (
        round(np.mean(heights), 2)
        if heights else 0
    )

    stats["Minimum Width"] = min(widths) if widths else 0
    stats["Maximum Width"] = max(widths) if widths else 0

    stats["Minimum Height"] = min(heights) if heights else 0
    stats["Maximum Height"] = max(heights) if heights else 0

    stats["Average Brightness"] = (
        round(np.mean(brightness), 2)
        if brightness else 0
    )

    stats["Image Formats"] = dict(formats)
    stats["Label Distribution"] = dict(labels)

    return stats


# ============================================================
# Main
# ============================================================

def main():

    images = find_images()

    print("\n")
    print("=" * 70)
    print("SCREENSHOT DATASET AUDIT")
    print("=" * 70)

    print(f"\nImages Found : {len(images)}\n")

    stats = dataset_statistics(images)

    print(f"Total Images        : {stats['Total Images']}")
    print(f"Corrupted Images    : {stats['Corrupted Images']}")

    print(f"Average Width       : {stats['Average Width']}")
    print(f"Average Height      : {stats['Average Height']}")

    print(f"Minimum Width       : {stats['Minimum Width']}")
    print(f"Maximum Width       : {stats['Maximum Width']}")

    print(f"Minimum Height      : {stats['Minimum Height']}")
    print(f"Maximum Height      : {stats['Maximum Height']}")

    print(f"Average Brightness  : {stats['Average Brightness']}")

    print("\nImage Formats")

    for fmt, count in stats["Image Formats"].items():

        print(f"   {fmt} : {count}")

    print("\nLabel Distribution")

    for label, count in stats["Label Distribution"].items():

        print(f"   {label} : {count}")

    print("\n")
    print("=" * 70)
    print("Audit Completed")
    print("=" * 70)


if __name__ == "__main__":
    main()