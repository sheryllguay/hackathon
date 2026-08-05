#!/usr/bin/env python3
import sys
import os
import json
import re

def update_framework(writeup_path):
    print(f"[*] Processing writeup: {writeup_path}")
    if not os.path.exists(writeup_path):
        print(f"[-] Writeup file not found: {writeup_path}")
        return
        
    with open(writeup_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Extract Metadata
    category_match = re.search(r'Category:\s*(.*)', content, re.IGNORECASE)
    payload_match = re.search(r'Payload:\s*`(.*)`', content, re.IGNORECASE)
    
    category = category_match.group(1).strip() if category_match else "General"
    payload = payload_match.group(1).strip() if payload_match else None
    
    print(f"[+] Parsed Category: {category}")
    if payload:
        print(f"[+] Parsed Payload: {payload}")
        # Append payload to payloads directory if it does not exist
        payload_file = os.path.join("hackathon", "payloads", f"{category.upper()}.txt")
        if os.path.exists(payload_file):
            with open(payload_file, 'r+', encoding='utf-8') as pf:
                payloads_content = pf.read()
                if payload not in payloads_content:
                    pf.write(f"\n# Added from writeup: {writeup_path}\n{payload}\n")
                    print(f"[+] Added payload to {payload_file}")
                else:
                    print(f"[*] Payload already exists in {payload_file}")
                    
    # Log addition to notes
    notes_file = os.path.join("hackathon", "notes", "README.md")
    if os.path.exists(notes_file):
        with open(notes_file, 'a', encoding='utf-8') as nf:
            nf.write(f"\n- Integrated solutions from writeup: [{os.path.basename(writeup_path)}](../solved/{os.path.basename(writeup_path)})\n")
            print(f"[+] Logged writeup reference in {notes_file}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path_to_writeup_markdown>")
        sys.exit(1)
    update_framework(sys.argv[1])
