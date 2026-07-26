# Email Detection Model

## Dataset

- Total Emails: 85,352
- Balanced Dataset
- Multiple public phishing datasets merged

## Preprocessing

- Lowercase
- URL tokenization
- Email tokenization
- IP tokenization
- Lemmatization
- Stopword removal

## Vectorization

TF-IDF

Max Features: 10,000

N-grams: (1,2)

## Model Comparison

| Model | Accuracy | F1 |
|--------|---------:|----:|
| Linear SVM | 98.41% | 98.44% |
| Random Forest | 98.20% | 98.22% |
| Logistic Regression | 97.94% | 97.98% |
| Naive Bayes | 95.27% | 95.19% |

## Selected Model

Linear SVM