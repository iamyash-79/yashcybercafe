import sqlite3

# Connect to the catalog database
conn = sqlite3.connect("products.db")
cursor = conn.cursor()

# Update all products with seller_id 8 to 42
cursor.execute("UPDATE product SET seller_id = 42 WHERE seller_id = 8")

# Commit and close
conn.commit()
conn.close()

print("✅ seller_id updated from 8 to 42")
