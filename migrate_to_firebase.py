"""
Coffee Beats → Firebase Firestore migration script.
Uses the Firestore REST API (no service account required).
"""

import json, re, uuid, datetime, requests, openpyxl, csv, os, sys, time

PROJECT_ID  = "coffeebeats-79200"
API_KEY     = "AIzaSyA9fMlRqhrCMsXHdj1JYd2EM3yOmai2VAA"
BASE_URL    = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents"
HTML_PATH   = os.path.join(os.path.dirname(__file__), ".claude/worktrees/nostalgic-curie-8318d5/index.html")
DATA_DIR    = os.path.dirname(__file__)

# ── Firestore value helpers ────────────────────────────────────────────────────

def fs_val(v):
    if v is None:                        return {"nullValue": None}
    if isinstance(v, bool):              return {"booleanValue": v}
    if isinstance(v, int):               return {"integerValue": str(v)}
    if isinstance(v, float):
        if v != v: return {"nullValue": None}   # NaN
        return {"doubleValue": v}
    if isinstance(v, str):               return {"stringValue": v}
    if isinstance(v, list):
        return {"arrayValue": {"values": [fs_val(i) for i in v]}}
    if isinstance(v, dict):
        return {"mapValue": {"fields": {k: fs_val(vv) for k, vv in v.items()}}}
    return {"stringValue": str(v)}

def fs_doc(data):
    return {"fields": {k: fs_val(v) for k, v in data.items()}}

# ── Firestore write ────────────────────────────────────────────────────────────

def write_doc(collection, doc_id, data):
    url = f"{BASE_URL}/{collection}/{doc_id}?key={API_KEY}"
    body = fs_doc(data)
    # PATCH with updateMask to set all fields
    field_paths = list(data.keys())
    mask = "&".join(f"updateMask.fieldPaths={k}" for k in field_paths)
    r = requests.patch(f"{url}&{mask}", json=body, timeout=30)
    if not r.ok:
        print(f"  ERROR {r.status_code}: {r.text[:300]}")
        return False
    return True

# ── Parse seed data from HTML ──────────────────────────────────────────────────

def extract_json_script(html, script_id):
    m = re.search(rf'<script id="{script_id}"[^>]*>(.*?)</script>', html, re.DOTALL)
    return json.loads(m.group(1)) if m else None

with open(HTML_PATH, encoding="utf-8") as f:
    html = f.read()

seed_inv  = extract_json_script(html, "seed-inventory")
seed_menu = extract_json_script(html, "seed-menu")

# ── Build inventory items ──────────────────────────────────────────────────────

def new_id():
    return str(uuid.uuid4())

items = []
for i, x in enumerate(seed_inv["items"]):
    items.append({
        "id":       f"inv_{str(i+1).zfill(4)}",
        "name":     x["name"],
        "unit":     x["unit"],
        "category": x["category"],
        "active":   True,
    })

by_name = {it["name"]: it for it in items}

snapshot_entries = []
for x in seed_inv["items"]:
    it = by_name.get(x["name"])
    if not it: continue
    snapshot_entries.append({"item_id": it["id"], "branch": "maadi", "qty": float(x.get("maadi_qty") or 0)})
    snapshot_entries.append({"item_id": it["id"], "branch": "zawya", "qty": float(x.get("zawya_qty") or 0)})

snapshot = {
    "id":         new_id(),
    "as_of":      seed_inv.get("as_of", "2026-03-31"),
    "created_at": "2026-03-31T23:59:00.000Z",
    "created_by": "seed",
    "entries":    snapshot_entries,
    "notes":      "Opening snapshot loaded from Inventory Status.xlsx (March 31, 2026).",
}

# ── Build menu (enriched with BF costs from Menu Engineering Report) ───────────

# Read BF costs from Ref sheets
cost_map = {}  # name → cost_bf
try:
    wb_me = openpyxl.load_workbook(
        os.path.join(DATA_DIR, "Coffee Beats — Menu Engineering Report.xlsx"),
        data_only=True
    )
    for sheet_name in ["Ref — Zawya", "Ref — Maadi"]:
        ws = wb_me[sheet_name]
        for row in ws.iter_rows(min_row=4, values_only=True):
            if row[0] and row[7] is not None:
                name = str(row[0]).strip()
                cost = float(row[7]) if isinstance(row[7], (int, float)) else None
                if cost and name not in cost_map:
                    cost_map[name] = cost
    print(f"  Loaded {len(cost_map)} BF cost entries from Menu Engineering Report")
except Exception as e:
    print(f"  Warning: could not read Menu Engineering Report: {e}")

menu = []
for it in seed_menu["items"]:
    m = dict(it)
    # Enrich cost from BF data
    bf = cost_map.get(m["name"])
    if bf and not m.get("cost_egp"):
        m["cost_egp"] = bf
    menu.append(m)

# ── Build users ────────────────────────────────────────────────────────────────

# Fixed UUIDs so migration is idempotent
USER_IDS = {
    "owner":        "u-owner-haidi-0001",
    "accountant":   "u-acct-hesham-0002",
    "hb_maadi":     "u-hb-maadi-00003",
    "hb_zawya":     "u-hb-zawya-00004",
    "barista1":     "u-barista-100005",
    "barista2":     "u-barista-200006",
    "barista3":     "u-barista-300007",
    "khaled":       "u-barista-khaled08",
}

# Read staff salaries from attendance tracker
salary_config = {}
try:
    wb_att = openpyxl.load_workbook(
        os.path.join(DATA_DIR, "Coffee_Beats_Attendance_Tracker.xlsx"),
        data_only=True
    )
    ws_staff = wb_att["Staff"]
    name_to_uid = {
        "seif": USER_IDS["barista1"],
    }
    for row in ws_staff.iter_rows(min_row=4, values_only=True):
        if not row[1]: continue
        name = str(row[1]).strip()
        daily  = float(row[3]) if isinstance(row[3], (int, float)) else None
        monthly = float(row[4]) if isinstance(row[4], (int, float)) else None
        if not monthly and daily:
            monthly = daily * 30
        uid = name_to_uid.get(name.lower())
        if uid and monthly:
            salary_config[uid] = {
                "monthly_salary": monthly,
                "updated_at":     "2026-05-01T00:00:00.000Z",
                "updated_by":     "migration",
            }
    print(f"  Loaded {len(salary_config)} salary entries from Attendance Tracker")
except Exception as e:
    print(f"  Warning: could not read Attendance Tracker: {e}")

_seeded_ids = {
    "khaled":   USER_IDS["khaled"],
    "barista3": USER_IDS["barista3"],
}

users = [
    {"id": USER_IDS["owner"],      "name": "Haïdi (Owner)",       "role": "owner",        "pin": "1111", "branches": ["maadi","zawya"], "active": True},
    {"id": USER_IDS["accountant"], "name": "Hesham (Accountant)",  "role": "accountant",   "pin": "9999", "branches": ["maadi","zawya"], "active": True},
    {"id": USER_IDS["hb_maadi"],   "name": "Head Barista Maadi",   "role": "head_barista", "pin": "2222", "branches": ["maadi"],         "active": True},
    {"id": USER_IDS["hb_zawya"],   "name": "Head Barista Zawya",   "role": "head_barista", "pin": "3333", "branches": ["zawya"],         "active": True},
    {"id": USER_IDS["barista1"],   "name": "Seif",                 "role": "barista",      "pin": "4444", "branches": ["maadi","zawya"], "active": True},
    {"id": USER_IDS["barista2"],   "name": "Barista 2",            "role": "barista",      "pin": "5555", "branches": ["maadi","zawya"], "active": True},
    {"id": USER_IDS["barista3"],   "name": "Barista 3",            "role": "barista",      "pin": "6666", "branches": ["maadi","zawya"], "active": True},
    {"id": USER_IDS["khaled"],     "name": "Khaled",               "role": "barista",      "pin": "7777", "branches": ["maadi","zawya"], "active": True},
]

# ── Settings & config ─────────────────────────────────────────────────────────

settings = {
    "currency":           "EGP",
    "branches":           ["maadi", "zawya"],
    "team_code":          "coffeeteam2026",
    "head_barista_email": "",
    "owner_email":        "coffeebeats@haidiyacoub.com",
    "last_sync":          None,
    "last_pull":          None,
}

branch_opening_times = {
    "maadi": {"morning": "10:00", "night": "16:00"},
    "zawya": {"morning": "12:00", "night": "18:00"},
}

# Petty cash opening entries
PETTY_IDS = {"maadi": new_id(), "zawya": new_id()}
petty_cash = [
    {"id": PETTY_IDS["maadi"], "branch": "maadi", "date": "2026-04-01", "type": "topup",
     "amount": 0, "balance_after": 0, "ref": "opening", "by": "seed",
     "at": "2026-04-01T00:00:00.000Z", "note": "Opening balance — set in Settings"},
    {"id": PETTY_IDS["zawya"], "branch": "zawya", "date": "2026-04-01", "type": "topup",
     "amount": 0, "balance_after": 0, "ref": "opening", "by": "seed",
     "at": "2026-04-01T00:00:00.000Z", "note": "Opening balance — set in Settings"},
]

# ── STATE CHUNKS ──────────────────────────────────────────────────────────────

chunks = {
    "config": {
        "settings":    settings,
        "salary_config": salary_config,
    },
    "users_items": {
        "users":       users,
        "items":       items,
        "menu":        menu,
        "snapshots":   [snapshot],
        "handbook_recipes":  [],
        "purchase_units":    {},
        "inventory_alerts":  {},
    },
    "waste":      {"waste": []},
    "purchases":  {"purchases": [], "petty_cash": petty_cash, "bank_ledger": []},
    "sales":      {"sales": [], "shifts": []},
    "operations": {"shift_closes": [], "cleaning_logs": [], "signin_stamps": []},
    "roster":     {"rosters": [], "roaster_schedules": [], "maadi_deposits": []},
    "hr":         {"salaries": [], "salary_loans": [], "overtime_logs": [],
                   "penalties": [], "deleted_penalties": [], "leaves": []},
    "overhead":   {"overheads": [], "overhead_presets": {}, "overhead_monthly_amts": {}},
    "media":      {"photo_log": [], "assets": []},
    "kpi":        {"kpi_manual": [], "customer_feedback": [], "alert_log": [], "kpi_settings": {}},
    "meta":       {
        "_seeded_ids":                    _seeded_ids,
        "_migration_khaled_role_fixed":   True,
        "version":                        1,
        "created_at":                     datetime.datetime.utcnow().isoformat() + "Z",
        "branch_opening_times":           branch_opening_times,
    },
}

# ── Push to Firestore ─────────────────────────────────────────────────────────

print("\n🚀  Pushing Coffee Beats state to Firestore…\n")
ok = 0
fail = 0
for chunk_name, data in chunks.items():
    sys.stdout.write(f"  Writing state/{chunk_name} … ")
    sys.stdout.flush()
    success = write_doc("state", chunk_name, data)
    if success:
        print("✓")
        ok += 1
    else:
        print("✗  FAILED")
        fail += 1
    time.sleep(0.3)   # avoid rate limiting

print(f"\n{'─'*50}")
print(f"Done — {ok} written, {fail} failed")
if fail == 0:
    print("✅  All Firestore documents created successfully!")
    print(f"   Project: {PROJECT_ID}")
    print("   Collection: state")
    print(f"   Documents: {list(chunks.keys())}")
else:
    print("⚠️  Some writes failed. Check Firestore security rules — make sure")
    print("   reads/writes are allowed, or the database is in test mode.")
