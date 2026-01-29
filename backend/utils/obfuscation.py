import re

shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly']

def obfuscation_score(text):
    score = 0

    if len(text) > 100:
        score += 1

    if re.search(r'\d{3,}', text):
        score += 1

    for s in shorteners:
        if s in text:
            score += 2

    return score
