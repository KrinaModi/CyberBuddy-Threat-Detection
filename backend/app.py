import sys
import os
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from flask import Flask, render_template, request
import pickle

from utils.preprocessing import clean_text
from utils.features import extract_features
from sklearn.linear_model import LogisticRegression
import pandas as pd

app = Flask(__name__, template_folder='../frontend/templates')

# Load and train model once (simple approach)
data = pd.read_csv('datasets/email_dataset.csv')
data['cleaned_text'] = data['text_or_url'].apply(clean_text)
X = pd.DataFrame(list(data['cleaned_text'].apply(extract_features)))
y = data['label']

model = LogisticRegression(max_iter=1000, class_weight={0:1, 1:2})
model.fit(X, y)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        user_input = request.form['message']
        cleaned = clean_text(user_input)
        features = extract_features(cleaned)
        df = pd.DataFrame([features])
        prediction = model.predict(df)[0]

        result = "⚠️ Threat Detected" if prediction == 1 else "✅ Safe Content"

    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
