import sqlite3

def add_missing_columns():
    conn = sqlite3.connect('orders.db')
    cursor = conn.cursor()

    # ✅ Add user_payment_confirmed column
    try:
        cursor.execute("ALTER TABLE orders ADD COLUMN user_payment_confirmed INTEGER DEFAULT 0;")
        conn.commit()
        print("✅ Column 'user_payment_confirmed' added successfully.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print("⚠️ Column 'user_payment_confirmed' already exists.")
        else:
            print(f"❌ Error: {e}")

    # ✅ Add user_name column
    try:
        cursor.execute("ALTER TABLE orders ADD COLUMN user_name TEXT;")
        conn.commit()
        print("✅ Column 'user_name' added successfully.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print("⚠️ Column 'user_name' already exists.")
        else:
            print(f"❌ Error: {e}")

    # ✅ Add user_contact column
    try:
        cursor.execute("ALTER TABLE orders ADD COLUMN user_contact TEXT;")
        conn.commit()
        print("✅ Column 'user_contact' added successfully.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print("⚠️ Column 'user_contact' already exists.")
        else:
            print(f"❌ Error: {e}")

    conn.close()

if __name__ == "__main__":
    add_missing_columns()
