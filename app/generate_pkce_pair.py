import secrets
import hashlib
import base64

def generate_pkce_pair():
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b'=').decode('utf-8')
    return code_verifier, code_challenge

providers = ["GOOGLE", "GITHUB", "FACEBOOK", "MICROSOFT"]
for provider in providers:
    verifier, challenge = generate_pkce_pair()
    print(f"{provider}_CODE_VERIFIER={verifier}")
    print(f"{provider}_CODE_CHALLENGE={challenge}")
    print()
