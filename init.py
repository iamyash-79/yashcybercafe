import mysql.connector

def get_mysql_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Yashwant@7987",
        database="cybercafe_app"
    )

def show_table_columns(table_name):
    conn = get_mysql_connection()
    cur = conn.cursor()
    cur.execute(f"SHOW COLUMNS FROM {table_name}")
    columns = cur.fetchall()
    conn.close()

    print(f"\n🔍 Columns in '{table_name}':")
    for col in columns:
        print(f"📌 {col[0]} - {col[1]}")

# ✅ Example usage
tables = ['users', 'products', 'services', 'bills', 'bill_items', 'orders', 'security_questions']

for table in tables:
    show_table_columns(table)
