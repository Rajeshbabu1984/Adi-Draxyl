import sqlite3
import hashlib

def reset_password():
    """Simple password reset tool"""
    print("🔑 Draxyl Password Reset Tool\n")
    
    # Connect to database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Show all users
    cursor.execute('SELECT id, name, email FROM users')
    users = cursor.fetchall()
    
    if not users:
        print("❌ No users found in database!")
        conn.close()
        return
    
    print("📋 Existing users:")
    for user in users:
        print(f"   ID: {user[0]} | Name: {user[1]} | Email: {user[2]}")
    
    print("\n" + "="*50)
    
    # Get email to reset
    email = input("\n📧 Enter email to reset password: ").strip()
    
    # Check if user exists
    cursor.execute('SELECT id, name FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    
    if not user:
        print(f"❌ User with email '{email}' not found!")
        conn.close()
        return
    
    print(f"✅ Found user: {user[1]}")
    
    # Get new password
    new_password = input("🔐 Enter new password (minimum 6 characters): ").strip()
    
    if len(new_password) < 6:
        print("❌ Password must be at least 6 characters!")
        conn.close()
        return
    
    # Hash password
    hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
    
    # Update password
    cursor.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_password, email))
    conn.commit()
    conn.close()
    
    print(f"\n✅ Password updated successfully for {user[1]}!")
    print(f"📧 Email: {email}")
    print(f"🔐 New Password: {new_password}")
    print("\n👉 You can now login with these credentials!")

if __name__ == '__main__':
    try:
        reset_password()
    except KeyboardInterrupt:
        print("\n\n❌ Cancelled by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
