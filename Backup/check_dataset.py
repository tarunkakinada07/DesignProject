from backend.app.database.connection import init_db, get_db_connection

init_db()

with get_db_connection() as conn:
    cursor = conn.cursor()
    cursor.execute(
        "SELECT label, parse_status, COUNT(*) "
        "FROM samples GROUP BY label, parse_status"
    )
    rows = cursor.fetchall()

    if not rows:
        print("No samples found in the database.")
    else:
        for row in rows:
            print(tuple(row))
