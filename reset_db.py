"""Empty all stored runs (use before real grader Checks):  python reset_db.py --yes"""
import sys
from dotenv import load_dotenv
load_dotenv()
if "--yes" not in sys.argv: raise SystemExit("This deletes ALL stored runs. Re-run with --yes")
import main
with main.Conn() as c:
    c.x("DELETE FROM events"); c.x("DELETE FROM runs")
print("cleared:", "postgres" if main.PG else main.DB)
