#!/usr/bin/env python3
"""
API Lab — Servidor Flask con datos reales de pentesting/linux
Pensado para correr desde un pendrive con Python 3 + Flask.

Uso:
    pip install flask
    python lab.py
    # abrí http://localhost:5000
"""
import json
import os
import sys
from pathlib import Path
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory

# ---------------------------------------------------------------------
# RUTAS — soporta correr desde USB sin asumir CWD
# ---------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR.parent / "data"

# ---------------------------------------------------------------------
# APP
# ---------------------------------------------------------------------
app = Flask(__name__, static_folder=None)
app.config["JSON_SORT_KEYS"] = False

# DB en memoria (se puede cambiar a SQLite si querés persistencia)
DB = {
    "loaded": {},        # { "privesc": {...}, "commands": {...} }
    "queries": [],       # log de requests
    "history": [],       # cambios de estado
    "started_at": datetime.utcnow().isoformat() + "Z"
}

# ---------------------------------------------------------------------
# CARGA DE DATASETS
# ---------------------------------------------------------------------
def load_dataset_file(filename):
    path = DATA_DIR / filename
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

DATASETS = {
    "privesc":    load_dataset_file("privesc.json"),
    "commands":   load_dataset_file("commands.json"),
}

# Si querés sumar más datasets, agregalos al directorio data/

# ---------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------
def log_query(method, path):
    DB["queries"].append({
        "method": method,
        "path": path,
        "ts": datetime.utcnow().isoformat() + "Z"
    })

def count_commands(ds):
    if not ds or "categories" not in ds:
        return 0
    return sum(len(cat.get("commands", [])) for cat in ds["categories"].values())

def count_categories(ds):
    if not ds or "categories" not in ds:
        return 0
    return len(ds["categories"])

# ---------------------------------------------------------------------
# RUTAS — API
# ---------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "static_index.html")

@app.route("/api/v1/help")
def help():
    log_query("GET", "/api/v1/help")
    return jsonify({
        "lab": "API Lab — Pentesting & Linux",
        "endpoints": [
            {"method": "GET",    "path": "/api/v1/datasets",              "desc": "Lista datasets disponibles y cargados en DB"},
            {"method": "GET",    "path": "/api/v1/datasets/<name>",       "desc": "Preview o contenido completo de un dataset"},
            {"method": "POST",   "path": "/api/v1/datasets/<name>/load",  "desc": "Carga un dataset en la DB"},
            {"method": "DELETE", "path": "/api/v1/datasets/<name>",       "desc": "Descarga un dataset de la DB"},
            {"method": "GET",    "path": "/api/v1/commands",              "desc": "Busca comandos. Params: ?cat= ?q= ?severity= ?dataset="},
            {"method": "GET",    "path": "/api/v1/commands/<id>",         "desc": "Detalle de un comando por ID"},
            {"method": "GET",    "path": "/api/v1/shells",                "desc": "Lista reverse shells"},
            {"method": "GET",    "path": "/api/v1/shells/<id>",           "desc": "Detalle de un shell"},
            {"method": "GET",    "path": "/api/v1/db",                    "desc": "Estado completo de la DB"},
            {"method": "DELETE", "path": "/api/v1/db",                    "desc": "Vacía la DB"},
            {"method": "GET",    "path": "/api/v1/queries",               "desc": "Log de queries realizadas"},
            {"method": "GET",    "path": "/api/v1/stats",                 "desc": "Estadísticas del lab"}
        ]
    })

@app.route("/api/v1/datasets", methods=["GET"])
def list_datasets():
    log_query("GET", "/api/v1/datasets")
    return jsonify({
        "available": [k for k, v in DATASETS.items() if v is not None],
        "loaded": list(DB["loaded"].keys()),
        "total_available": sum(1 for v in DATASETS.values() if v is not None),
        "total_loaded": len(DB["loaded"])
    })

@app.route("/api/v1/datasets/<name>", methods=["GET"])
def get_dataset(name):
    log_query("GET", f"/api/v1/datasets/{name}")
    if name in DB["loaded"]:
        return jsonify({"source": "db", **DB["loaded"][name]})
    if name not in DATASETS or DATASETS[name] is None:
        return jsonify({"error": f"Dataset '{name}' no existe", "available": list(DATASETS.keys())}), 404
    ds = DATASETS[name]
    return jsonify({
        "source": "remote",
        "name": ds.get("name"),
        "description": ds.get("description"),
        "categories": list(ds.get("categories", {}).keys()),
        "total_commands": count_commands(ds)
    })

@app.route("/api/v1/datasets/<name>/load", methods=["POST"])
def load_dataset(name):
    log_query("POST", f"/api/v1/datasets/{name}/load")
    if name not in DATASETS or DATASETS[name] is None:
        return jsonify({"error": f"Dataset '{name}' no existe", "available": list(DATASETS.keys())}), 404
    if name in DB["loaded"]:
        return jsonify({"msg": f"Dataset '{name}' ya estaba cargado", "loaded_at": DB["loaded"][name]["loaded_at"]}), 200
    payload = json.loads(json.dumps(DATASETS[name]))  # deep copy
    payload["loaded_at"] = datetime.utcnow().isoformat() + "Z"
    DB["loaded"][name] = payload
    DB["history"].append({"action": "load", "dataset": name, "ts": payload["loaded_at"]})
    return jsonify({
        "msg": f"Dataset '{name}' cargado en DB",
        "total_commands": count_commands(payload),
        "total_categories": count_categories(payload),
        "loaded_at": payload["loaded_at"]
    }), 201

@app.route("/api/v1/datasets/<name>", methods=["DELETE"])
def unload_dataset(name):
    log_query("DELETE", f"/api/v1/datasets/{name}")
    if name not in DB["loaded"]:
        return jsonify({"error": f"Dataset '{name}' no está cargado"}), 404
    del DB["loaded"][name]
    DB["history"].append({"action": "unload", "dataset": name, "ts": datetime.utcnow().isoformat() + "Z"})
    return jsonify({"msg": f"Dataset '{name}' descargado de la DB"})

@app.route("/api/v1/commands", methods=["GET"])
def list_commands():
    log_query("GET", "/api/v1/commands")
    if not DB["loaded"]:
        return jsonify({
            "error": "DB vacía",
            "hint": "Cargá un dataset primero: POST /api/v1/datasets/privesc/load"
        }), 503

    cat = request.args.get("cat")
    q = request.args.get("q", "").lower()
    severity = request.args.get("severity")
    dataset = request.args.get("dataset")
    limit = int(request.args.get("limit", 100))

    results = []
    for ds_name, ds in DB["loaded"].items():
        if dataset and dataset != ds_name:
            continue
        for cat_key, cat_data in (ds.get("categories") or {}).items():
            if cat and cat != cat_key:
                continue
            if severity and cat_data.get("severity") != severity:
                continue
            for idx, cmd in enumerate(cat_data.get("commands", [])):
                if q and (q not in cmd.get("cmd", "").lower() and q not in cmd.get("desc", "").lower()):
                    continue
                results.append({
                    "id": f"{ds_name}/{cat_key}/{idx}",
                    "dataset": ds_name,
                    "category": cat_key,
                    "category_title": cat_data.get("title"),
                    "severity": cat_data.get("severity"),
                    "cmd": cmd.get("cmd"),
                    "desc": cmd.get("desc")
                })

    return jsonify({
        "count": len(results),
        "returned": min(limit, len(results)),
        "results": results[:limit]
    })

@app.route("/api/v1/commands/<path:cmd_id>")
def get_command(cmd_id):
    log_query("GET", f"/api/v1/commands/{cmd_id}")
    parts = cmd_id.split("/")
    if len(parts) != 3:
        return jsonify({"error": "ID inválido. Formato: dataset/category/index"}), 400
    ds_name, cat_key, idx_str = parts
    try:
        idx = int(idx_str)
    except ValueError:
        return jsonify({"error": "Index debe ser numérico"}), 400
    if ds_name not in DB["loaded"]:
        return jsonify({"error": f"Dataset '{ds_name}' no cargado"}), 404
    cat = DB["loaded"][ds_name].get("categories", {}).get(cat_key)
    if not cat:
        return jsonify({"error": f"Categoría '{cat_key}' no existe"}), 404
    if idx < 0 or idx >= len(cat.get("commands", [])):
        return jsonify({"error": f"Index {idx} fuera de rango"}), 404
    return jsonify({
        "id": cmd_id,
        "dataset": ds_name,
        "category": cat_key,
        "severity": cat.get("severity"),
        **cat["commands"][idx]
    })

@app.route("/api/v1/shells", methods=["GET"])
def list_shells():
    log_query("GET", "/api/v1/shells")
    shells = {}
    for ds in DB["loaded"].values():
        if "shells" in ds:
            shells.update(ds["shells"])
    if not shells:
        return jsonify({"error": "Sin shells cargados", "hint": "Cargá privesc dataset"}), 503
    return jsonify({"count": len(shells), "shells": shells})

@app.route("/api/v1/shells/<shell_id>")
def get_shell(shell_id):
    log_query("GET", f"/api/v1/shells/{shell_id}")
    for ds in DB["loaded"].values():
        if "shells" in ds and shell_id in ds["shells"]:
            return jsonify({"id": shell_id, **ds["shells"][shell_id]})
    return jsonify({"error": f"Shell '{shell_id}' no encontrado"}), 404

@app.route("/api/v1/db", methods=["GET"])
def db_state():
    log_query("GET", "/api/v1/db")
    return jsonify({
        "loaded_datasets": list(DB["loaded"].keys()),
        "total_commands": sum(count_commands(ds) for ds in DB["loaded"].values()),
        "total_categories": sum(count_categories(ds) for ds in DB["loaded"].values()),
        "queries_count": len(DB["queries"]),
        "history_count": len(DB["history"]),
        "started_at": DB["started_at"]
    })

@app.route("/api/v1/db", methods=["DELETE"])
def db_flush():
    log_query("DELETE", "/api/v1/db")
    prev = len(DB["loaded"])
    DB["loaded"] = {}
    DB["history"].append({"action": "flush", "ts": datetime.utcnow().isoformat() + "Z"})
    return jsonify({"msg": f"DB vaciada. {prev} datasets eliminados."})

@app.route("/api/v1/queries")
def get_queries():
    return jsonify({"count": len(DB["queries"]), "queries": DB["queries"][-50:]})

@app.route("/api/v1/stats")
def stats():
    log_query("GET", "/api/v1/stats")
    cat_counts = {}
    sev_counts = {}
    for ds in DB["loaded"].values():
        for cat_key, cat in (ds.get("categories") or {}).items():
            cat_counts[cat_key] = cat_counts.get(cat_key, 0) + len(cat.get("commands", []))
            sev = cat.get("severity", "unknown")
            sev_counts[sev] = sev_counts.get(sev, 0) + len(cat.get("commands", []))
    return jsonify({
        "by_category": cat_counts,
        "by_severity": sev_counts,
        "total_queries": len(DB["queries"])
    })

# ---------------------------------------------------------------------
# STATIC
# ---------------------------------------------------------------------
@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(BASE_DIR, filename)

# ---------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------
if __name__ == "__main__":
    port = 5000
    host = "127.0.0.1"
    if "--host" in sys.argv:
        i = sys.argv.index("--host")
        host = sys.argv[i + 1] if i + 1 < len(sys.argv) else "0.0.0.0"
    if "--port" in sys.argv:
        i = sys.argv.index("--port")
        port = int(sys.argv[i + 1])
    print(f"""
╔════════════════════════════════════════════════════════════╗
║           API LAB — Pentesting & Linux                     ║
║                                                            ║
║   Servidor:  http://{host}:{port}                           ║
║   Datos:     {len([v for v in DATASETS.values() if v])} datasets disponibles                ║
║                                                            ║
║   Endpoints clave:                                         ║
║     GET  /api/v1/help                                       ║
║     GET  /api/v1/datasets                                   ║
║     POST /api/v1/datasets/privesc/load                      ║
║     GET  /api/v1/commands?cat=suid&severity=critical        ║
║     GET  /api/v1/shells                                     ║
║                                                            ║
║   Ctrl+C para detener.                                     ║
╚════════════════════════════════════════════════════════════╝
""")
    app.run(host=host, port=port, debug=False)