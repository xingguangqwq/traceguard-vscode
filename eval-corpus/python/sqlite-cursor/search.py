import sqlite3
def search(request):
    sql = request.args.get("sql")
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    rows = cursor.execute(sql)
    return rows.fetchall()
