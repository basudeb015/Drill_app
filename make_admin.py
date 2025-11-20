import sqlite3

# 👇 change email if needed
email = "basubuet@gmail.com"

conn = sqlite3.connect("orders.db")
c = conn.cursor()

# Check if the user exists
c.execute("SELECT id, username, is_admin FROM users WHERE email=?", (email,))
user = c.fetchone()

if user:
    c.execute("UPDATE users SET is_admin=1 WHERE email=?", (email,))
    conn.commit()
    print(f"✅ {email} is now an admin!")
else:
    print(f"⚠️ No user found with email: {email}. Please register this user first.")

conn.close()
