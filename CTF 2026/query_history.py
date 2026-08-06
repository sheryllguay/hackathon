import sqlite3, os, sys

path = r'C:\Users\User\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History'
print('Path:', path, 'exists:', os.path.exists(path), 'size:', os.path.getsize(path))

uri = 'file:///' + path.replace('\\', '/') + '?mode=ro'
print('URI:', uri)
try:
    con = sqlite3.connect(uri, uri=True)
    cur = con.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cur.fetchall()]
    print('TABLES:', tables)
    if 'urls' in tables:
        cur.execute('SELECT url, title, last_visit_time FROM urls WHERE url LIKE "%pico%" OR url LIKE "%credential%" OR url LIKE "%crystal%" OR url LIKE "%flag%" OR url LIKE "%CTF%" ORDER BY last_visit_time DESC LIMIT 100')
        for row in cur.fetchall(): print(row)
    con.close()
except Exception as e:
    print('Error:', e)
