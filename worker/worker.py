import time, os, psycopg2
while True:
    try:
        c = psycopg2.connect(host="db", dbname="shop", user="shop",
                             password=os.environ["DB_PASSWORD"])
        cur = c.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS items(id serial, name text)")
        cur.execute("INSERT INTO items(name) VALUES (%s)", (f"job-{int(time.time())}",))
        c.commit(); c.close()
    except Exception as e:
        print("worker error:", e, flush=True)
    time.sleep(30)
