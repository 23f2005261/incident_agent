"""Run on your machine BEFORE deploying:  python check_db.py   (tests DATABASE_URL from .env)"""
import os
from dotenv import load_dotenv
load_dotenv()
url = os.getenv("DATABASE_URL", "").strip()
if not url.startswith(("postgres://", "postgresql://")): raise SystemExit("DATABASE_URL is missing or not a postgres URL. Fix .env first.")
if "[YOUR-PASSWORD]" in url or "[" in url: raise SystemExit("DATABASE_URL still has square brackets / the placeholder. Remove them (and URL-encode special characters).")
import main
with main.Conn() as c:
    c.x("INSERT INTO events(run_id,ev_key,req_hash,response_json) VALUES('__probe__','p','h','{}') ON CONFLICT DO NOTHING")
    n = c.x("SELECT count(*) AS n FROM events WHERE run_id='__probe__'").fetchone()['n']
    c.x("DELETE FROM events WHERE run_id='__probe__'")
print("probe rows:", n); print("OK: database storage works")
