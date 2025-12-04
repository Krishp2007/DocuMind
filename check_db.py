import sqlite3

# Connect to the database
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Get all data
cursor.execute("SELECT * FROM documents")
rows = cursor.fetchall()

print(f"Total Documents: {len(rows)}\n")

for row in rows:
    print("------------------------------------------------")
    print(f"ID: {row[0]}")
    print(f"File: {row[1]}")
    print(f"Uploader: {row[3]}")
    print(f"Category: {row[5]}")
    print(f"Tags: {row[9]}")
    print("------------------------------------------------")

conn.close()