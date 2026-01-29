seen_texts = {}

def repetition_score(text):
    if text in seen_texts:
        seen_texts[text] += 1
        return 1
    else:
        seen_texts[text] = 1
        return 0
