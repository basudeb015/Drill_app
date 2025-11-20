import sqlite3

conn = sqlite3.connect('orders.db')
c = conn.cursor()

print("\n🧾 All Users in Database:\n")
for row in c.execute("SELECT id, email, username, is_admin FROM users"):
    print(f"ID: {row[0]} | Email: {row[1]} | Username: {row[2]} | Admin: {row[3]}")

conn.close()
