# Crystal Peak (picoCTF) - Writeup

## Category: Web Exploitation - IDOR via MD5-Obfuscated Object Reference
## Difficulty: Easy

### Challenge Description
> Submit your email and password, and it redirects you to your profile. But be careful: just
> because access to the admin isn't directly exposed doesn't mean it's secure. Maybe someone
> forgot that obscurity isn't security... Can you find your way into the admin's profile?

Target: `http://crystal-peak.picoctf.net:52415/` (Node.js / Express, body-parser JSON)

### Recon
1. GET `/` returned the login page. An HTML comment leaked guest credentials:
   `<!-- Email: guest@picoctf.org Password: guest -->`.
2. POST `/login` with `{"email":"guest@picoctf.org","password":"guest"}` returned
   `302 Found` -> `Location: /profile/user/e93028bdc1aacdfb3687181f2031765d`.
3. GET that profile returned: `Access level: Guest (ID: 3000). Insufficient privileges to view
   classified data. Only top-tier users can access the flag.` — the page leaks the current user ID.
4. Observed the 32-hex profile token and confirmed `md5("3000") == e93028bdc1aacdfb3687181f2031765d`.
   So the "obfuscation" is just `md5(str(user_id))` — one-way, but trivially guessable.

### Exploitation
1. Profile URL scheme: `/profile/user/<md5(user_id)>`.
2. Enumerated IDs (1..24 and 2995..3025) by requesting each hashed URL.
3. ID `3019` -> `Welcome, admin! Here is the flag: picoCTF{id0r_unl0ck_ee526012}`.

### Flag
```
picoCTF{id0r_unl0ck_ee526012}
```

### Why It Worked
The application used unsalted MD5 of the numeric user ID as the only "security" for the profile
route and performed no authorization check. MD5 is deterministic and un-keyed, so any client can
reverse the scheme: pick candidate IDs, hash them, and request the profile. The profile page itself
leaked the guest's numeric ID (3000), which cracked the whole scheme in one step. This is an
Insecure Direct Object Reference (IDOR): the identifier was guessed, the server did not verify the
requester's access level.

### Lessons Learned
- **Obscurity is not security**: a hash used to hide an object ID is just an encoding once the
  scheme is known. Check the format of "opaque" URL tokens against common one-way functions
  (MD5/SHA-1/base64) with a value you already control (your own ID leaked on your profile page).
- **Read your own profile first**: it frequently prints your numeric/role identifier, which is the
  seed to crack the whole ID scheme.
- **Guess ranges smartly**: small integer ID spaces (1..20, or 3000-based after a "~20 employees"
  hint) are quickly enumerated. 404 = no such user; 200 + "admin" = win.
- Weak hash used as access control => use IDOR enumeration, not hash cracking.

### Reusable Artifacts
- Skill: `skills/web/AuthBypass.md` (IDOR decision-tree section)
- Script: `scripts/idor_enumerate.py` (new)
- Payloads: `payloads/AuthBypass.txt` (IDOR md5 enumeration)
- Notes: `notes/patterns.md`, `notes/lessons_learned.md`
- Playbook: `playbooks/picoCTF.md` (IDOR enumeration step)

### References
- OWASP: Insecure Direct Object References (A01:2021 Broken Access Control)
- PortSwigger: IDOR labs
