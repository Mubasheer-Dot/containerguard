from flask import Flask, jsonify
import os, psycopg2

app = Flask(__name__)

def db():
    return psycopg2.connect(host="db", dbname="shop", user="shop",
                            password=os.environ["DB_PASSWORD"])

@app.route("/health")
def health():
    return jsonify(status="ok")

@app.route("/items")
def items():
    with db() as c, c.cursor() as cur:
        cur.execute("CREATE TABLE IF NOT EXISTS items(id serial, name text)")
        cur.execute("SELECT id, name FROM items")
        return jsonify(cur.fetchall())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
