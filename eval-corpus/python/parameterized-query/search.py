import sqlite3

def search(request):
    name = request.args.get("name")
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    rows = cursor.execute("SELECT id FROM users WHERE name = ?", (name,))
    return rows.fetchall()
