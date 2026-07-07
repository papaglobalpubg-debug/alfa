"""CyberScope v7.9.x - Secret Generator (CLI)."""
import secrets
import string


def generate_jwt_secret(length: int = 64) -> str:
    return secrets.token_hex(length // 2)


def generate_password(length: int = 20) -> str:
    if length < 8:
        length = 8
    pools = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        '!@#$%^&*-_+=.',
    ]
    chars = [secrets.choice(p) for p in pools]
    all_chars = ''.join(pools)
    chars += [secrets.choice(all_chars) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return ''.join(chars)


if __name__ == '__main__':
    print('=' * 60)
    print('CyberScope v7.9.x - Secret Generator')
    print('=' * 60)
    print()
    print(f'JWT_SECRET="{generate_jwt_secret(64)}"')
    print(f'ADMIN_PASSWORD="{generate_password(20)}"')
    print()
    print('Copy these into your backend/.env file.')
    print('NEVER commit the real .env file to git.')
