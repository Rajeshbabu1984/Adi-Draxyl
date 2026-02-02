import sqlite3
from datetime import datetime

conn = sqlite3.connect('messaging.db')
cursor = conn.cursor()

# Delete old user statuses
cursor.execute('DELETE FROM user_status')

# Add statuses for all 4 users
for user_id in [1, 2, 3, 4]:
    cursor.execute('INSERT INTO user_status (user_id, status, last_seen) VALUES (?, ?, ?)',
                   (user_id, 'online', datetime.now()))

conn.commit()

# Verify
cursor.execute('SELECT * FROM user_status')
statuses = cursor.fetchall()
print("✅ Updated user statuses:")
for status in statuses:
    print(f"   User {status[0]}: {status[1]} (Last seen: {status[2]})")

conn.close()
