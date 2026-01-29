trusted_domains = ['google', 'amazon', 'microsoft', 'bank', 'paypal']

def sender_content_score(sender, text):
    score = 0
    sender = sender.lower()
    text = text.lower()

    for domain in trusted_domains:
        if domain in sender and domain not in text:
            score += 1

    return score
