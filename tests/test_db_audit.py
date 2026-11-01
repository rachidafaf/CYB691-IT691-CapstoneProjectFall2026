"""Quick SQLite DB audit — run directly to inspect all three tables."""
import sqlite3
import os

db = os.path.join(os.path.dirname(__file__), "..", "data", "telemetry.db")
conn = sqlite3.connect(db)
conn.row_factory = sqlite3.Row

# Tables
tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;").fetchall()
print("=== TABLES ===")
for t in tables:
    print(" -", t["name"])

# telemetry_events
row = conn.execute("SELECT COUNT(*) as total, SUM(ground_truth_label) as attacks FROM telemetry_events;").fetchone()
print(f"\n=== telemetry_events: {row['total']} rows | attacks={row['attacks']} benign={row['total'] - row['attacks']} ===")

cats = conn.execute("SELECT category, COUNT(*) as cnt FROM telemetry_events GROUP BY category;").fetchall()
for c in cats:
    print(f"  category={c['category']}  count={c['cnt']}")

# incident_metrics
im = conn.execute("SELECT report_id, generated_at, total_events FROM incident_metrics;").fetchall()
print(f"\n=== incident_metrics: {len(im)} report(s) ===")
for r in im:
    print(f"  {r['report_id']} | events={r['total_events']} | at={r['generated_at']}")

# ml_benchmarks
benchmarks = conn.execute(
    "SELECT model_name, model_type, accuracy, recall, false_positive_rate FROM ml_benchmarks ORDER BY benchmark_id;"
).fetchall()
print(f"\n=== ml_benchmarks: {len(benchmarks)} row(s) ===")
for b in benchmarks:
    print(f"  {b['model_name']} ({b['model_type']})  acc={b['accuracy']}%  recall={b['recall']}%  fpr={b['false_positive_rate']}%")

conn.close()
