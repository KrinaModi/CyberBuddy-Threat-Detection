import os
import cv2
import pandas as pd
import matplotlib.pyplot as plt

IMAGE_FOLDER = "../datasets/final_screenshots"
LABEL_FILE = "../datasets/screenshot_labels.csv"


def screenshot_eda():

    df = pd.read_csv(LABEL_FILE)

    print("=" * 60)
    print("SCREENSHOT DATASET EXPLORATORY DATA ANALYSIS")
    print("=" * 60)

    print("\nDataset Shape:")
    print(df.shape)

    print("\nLabel Distribution:")
    print(df["label"].value_counts())

    widths = []
    heights = []
    brightness = []

    image_formats = {}

    for image in df["image"]:

        path = os.path.join(IMAGE_FOLDER, image)

        img = cv2.imread(path)

        if img is None:
            continue

        h, w = img.shape[:2]

        widths.append(w)
        heights.append(h)

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        brightness.append(gray.mean())

        ext = os.path.splitext(image)[1].lower()

        image_formats[ext] = image_formats.get(ext, 0) + 1

    print("\nAverage Width :", sum(widths) / len(widths))
    print("Average Height:", sum(heights) / len(heights))

    print("\nMinimum Width :", min(widths))
    print("Maximum Width :", max(widths))

    print("\nMinimum Height:", min(heights))
    print("Maximum Height:", max(heights))

    print("\nAverage Brightness:", sum(brightness) / len(brightness))

    print("\nImage Formats:")

    for fmt, count in image_formats.items():
        print(fmt, ":", count)

    plt.figure(figsize=(6,4))
    df["label"].value_counts().plot(kind="bar")
    plt.title("Screenshot Labels")
    plt.xlabel("Label")
    plt.ylabel("Count")
    plt.show()

    plt.figure(figsize=(8,4))
    plt.hist(widths, bins=20)
    plt.title("Image Width Distribution")
    plt.xlabel("Width")
    plt.ylabel("Frequency")
    plt.show()

    plt.figure(figsize=(8,4))
    plt.hist(heights, bins=20)
    plt.title("Image Height Distribution")
    plt.xlabel("Height")
    plt.ylabel("Frequency")
    plt.show()

    plt.figure(figsize=(8,4))
    plt.hist(brightness, bins=20)
    plt.title("Brightness Distribution")
    plt.xlabel("Brightness")
    plt.ylabel("Images")
    plt.show()

    plt.figure(figsize=(12,6))

    for i in range(min(6, len(df))):
        img = cv2.imread(os.path.join(IMAGE_FOLDER, df.iloc[i]["image"]))

        if img is None:
            continue

        img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)

        plt.subplot(2, 3, i + 1)
        plt.imshow(img)
        plt.title(f"Label: {df.iloc[i]['label']}")
        plt.axis("off")

    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    screenshot_eda()