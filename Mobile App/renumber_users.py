import sqlite3

# Connect to the database
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# Get all users ordered by their current ID
cursor.execute('SELECT id, name, email, password, created_at FROM users ORDER BY id')
users = cursor.fetchall()

print(f"Found {len(users)} users to renumber")
print("Current IDs:", [user[0] for user in users])

# Create a temporary table with new structure
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

# Insert users with sequential IDs starting from 1
for user in users:
    old_id, name, email, password, created_at = user
    cursor.execute('''
        INSERT INTO users_new (name, email, password, created_at)
        VALUES (?, ?, ?, ?)
    ''', (name, email, password, created_at))
    print(f"Renumbered user: {name} (was ID {old_id}, now ID {cursor.lastrowid})")

# Drop old table and rename new table
cursor.execute('DROP TABLE users')
cursor.execute('ALTER TABLE users_new RENAME TO users')

conn.commit()

# Verify the changes
cursor.execute('SELECT id, name, email FROM users ORDER BY id')
new_users = cursor.fetchall()
print("\n✅ Database updated successfully!")
print("New sequential IDs:")
for user in new_users:
    print(f"  ID {user[0]}: {user[1]} ({user[2]})")

# Get the next auto-increment value
cursor.execute("SELECT seq FROM sqlite_sequence WHERE name='users'")
seq_result = cursor.fetchone()
if seq_result:
    print(f"\n📊 Next user will be ID: {seq_result[0] + 1}")

conn.close()
