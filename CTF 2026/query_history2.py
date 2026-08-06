import sqlite3, os

path = r'C:\Users\User\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History'
uri = 'file:///' + path.replace('\\', '/') + '?mode=ro'

con = sqlite3.connect(uri, uri=True)
cur = con.cursor()

# Last 50 urls by visit time
cur.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 50")
for row in cur.fetchall():
    print(row)

print("\n--- picoCTF search ---")
cur.execute("SELECT url, title, last_visit_time FROM urls WHERE url LIKE '%pico%' OR url LIKE '%Pico%' LIMIT 30")
for row in cur.fetchall():
    print(row)

print("\n--- credential/crystal search ---")
cur.execute("SELECT url, title, last_visit_time FROM urls WHERE url LIKE '%credential%' OR url LIKE '%crystal%' OR url LIKE '%stuffing%' LIMIT 30")
for row in cur.fetchall():
    print(row)

con.close()
