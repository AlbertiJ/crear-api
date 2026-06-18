#!/usr/bin/env python3
"""
API Lab — Servidor Flask con datos reales de pentesting/linux
Pensado para correr desde un pendrive con Python 3 + Flask.

Uso:
    pip install flask
    python lab.py
    # abrí http://localhost:5000

Créditos:
    Idea y desarrollo:    Juan Alberti
    Programación:         MiniMax (Mavis)
"""
import json
import os
import random
import sys
from pathlib import Path
from datetime import datetime, timezone

def utc_now_iso():
    """ISO-8601 en UTC con sufijo 'Z' (compat con formato anterior)."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
from flask import Flask, jsonify, request, send_from_directory

# ---------------------------------------------------------------------
# RUTAS — soporta correr desde USB sin asumir CWD
# ---------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR.parent / "data"
DOCS_DIR = BASE_DIR.parent / "docs"

# ---------------------------------------------------------------------
# APP
# ---------------------------------------------------------------------
app = Flask(__name__, static_folder=None)
app.config["JSON_SORT_KEYS"] = False

# ---------------------------------------------------------------------
# CORS — para que option2/static_index.html (abierto desde file:// o
# desde otro origen) pueda hacer fetch al Flask. Sin esto, el browser
# bloquea todas las requests por same-origin policy.
# ---------------------------------------------------------------------
@app.after_request
def add_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Max-Age"]      = "3600"
    return resp

@app.route("/<path:_any>", methods=["OPTIONS"])
def cors_preflight(_any):
    """Responde 200 a cualquier preflight CORS (OPTIONS)."""
    return jsonify({}), 200

# DB en memoria (se puede cambiar a SQLite si querés persistencia)
DB = {
    "loaded": {},        # { "privesc": {...}, "commands": {...} }
    "queries": [],       # log de requests
    "history": [],       # cambios de estado
    "started_at": utc_now_iso()
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
    "clientes":   load_dataset_file("clientes.json"),
}

# ---------------------------------------------------------------------
# CATÁLOGO DE ENDPOINTS — fuente única para /api/v1/help y /help.txt
# ---------------------------------------------------------------------
ENDPOINTS_CATALOG = [
    # ---- Discovery / reconocimiento ----
    {"method": "GET",    "path": "/api/v1/discovery",      "cat": "descubrimiento",
     "short": "Info disclosure inicial del lab",
     "long":  "Devuelve información básica del lab: nombre, versión, datasets disponibles y cargados, api_root, links clave, conteo total de endpoints. Es el primer pedido que conviene hacer para reconocer el server. Soporta OPTIONS con headers Allow y X-Discovery-Methods (estilo CORS).",
     "params": [], "example": "curl http://127.0.0.1:5050/api/v1/discovery"},
    {"method": "GET",    "path": "/api/v1/fingerprint",    "cat": "descubrimiento",
     "short": "Fingerprint del server (framework, versión, headers)",
     "long":  "Devuelve el fingerprint del server: framework (Flask), versión exacta, versión de Python, content-type, encoding, si tiene CORS, auth, rate limit y debug mode. Sirve para identificar la pila tecnológica.",
     "params": [], "example": "curl http://127.0.0.1:5050/api/v1/fingerprint"},
    {"method": "GET",    "path": "/api/v1/routes",         "cat": "descubrimiento",
     "short": "Mapa completo de todas las rutas registradas",
     "long":  "Devuelve la lista completa de rutas registradas en Flask con sus métodos HTTP y nombre interno del endpoint. Es el mapa de superficie de ataque: muestra todo lo que el server sabe hacer.",
     "params": [], "example": "curl http://127.0.0.1:5050/api/v1/routes"},
    {"method": "GET",    "path": "/api/v1/health",         "cat": "descubrimiento",
     "short": "Health check básico del server",
     "long":  "Devuelve un health check simple: status, hora de arranque, cantidad de datasets disponibles y cargados, y timestamp actual. Útil para monitoreo y para confirmar que el server responde.",
     "params": [], "example": "curl http://127.0.0.1:5050/api/v1/health"},
    {"method": "GET",    "path": "/api/v1/severities",     "cat": "descubrimiento",
     "short": "Lista de severidades con conteo de comandos",
     "long":  "Devuelve las severidades presentes en los datasets cargados (info, low, medium, high, critical) con la cantidad de comandos que tiene cada una. Si la DB está vacía devuelve un hint para cargar un dataset primero.",
     "params": [], "example": "curl http://127.0.0.1:5050/api/v1/severities"},
    {"method": "GET",    "path": "/api/v1/categories",     "cat": "descubrimiento",
     "short": "Lista de categorías cross-dataset con metadata",
     "long":  "Devuelve la lista completa de categorías presentes en los datasets cargados, con su dataset, título, severidad y cantidad de comandos. Sirve para entender qué hay cargado antes de filtrar.",
     "params": [], "example": "curl http://127.0.0.1:5050/api/v1/categories"},
    {"method": "GET",    "path": "/api/v1/schemas/<name>", "cat": "descubrimiento",
     "short": "Schema/estructura de un dataset",
     "long":  "Devuelve la forma/estructura de un dataset: nombre, descripción, lista de categorías, conteo de comandos y categorías, lista de shells (si los tiene), un comando de ejemplo y un esqueleto de la estructura JSON esperada. Sirve para entender qué campos tiene cada item sin tener que cargar todo.",
     "params": [{"name": "name", "in": "path", "required": True, "type": "string", "desc": "Nombre del dataset (privesc, commands)"}],
     "example": "curl http://127.0.0.1:5050/api/v1/schemas/privesc"},
    {"method": "GET",    "path": "/api/v1/search",         "cat": "descubrimiento",
     "short": "Búsqueda full-text cross-dataset",
     "long":  "Hace una búsqueda libre sobre los datasets cargados: busca el texto en el comando (cmd), en la descripción (desc) y también en los reverse shells (id, payload, desc). Devuelve hasta 50 resultados combinando comandos y shells.",
     "params": [
         {"name": "q",      "in": "query", "required": True,  "type": "string", "desc": "Texto a buscar"},
         {"name": "limit",  "in": "query", "required": False, "type": "int",    "desc": "Máximo de resultados (default 50)"},
     ],
     "example": "curl 'http://127.0.0.1:5050/api/v1/search?q=suid'"},
    {"method": "GET",    "path": "/api/v1/random",         "cat": "descubrimiento",
     "short": "Devuelve un comando aleatorio",
     "long":  "Elige un comando al azar de los datasets cargados. Acepta filtros opcionales por dataset y por severidad. Útil para challenges, repasar o simplemente inspirarse.",
     "params": [
         {"name": "dataset",  "in": "query", "required": False, "type": "string", "desc": "Filtrar por dataset (privesc, commands)"},
         {"name": "severity", "in": "query", "required": False, "type": "string", "desc": "Filtrar por severidad (info, low, medium, high, critical)"},
     ],
     "example": "curl 'http://127.0.0.1:5050/api/v1/random?severity=critical'"},

    # ---- Datasets ----
    {"method": "GET",    "path": "/api/v1/datasets",       "cat": "datasets",
     "short": "Lista datasets disponibles y cargados",
     "long":  "Muestra qué datasets existen en la carpeta data/ y cuáles están cargados en la DB en memoria. También devuelve los totales. La DB arranca vacía cada vez que se inicia el server.",
     "params": [], "example": "curl http://127.0.0.1:5050/api/v1/datasets"},
    {"method": "GET",    "path": "/api/v1/datasets/<name>","cat": "datasets",
     "short": "Preview o contenido de un dataset",
     "long":  "Si el dataset está cargado en la DB, devuelve su contenido completo. Si NO está cargado, devuelve un preview con nombre, descripción, lista de categorías y total de comandos. Sirve para mirar antes de cargar.",
     "params": [{"name": "name", "in": "path", "required": True, "type": "string", "desc": "Nombre del dataset"}],
     "example": "curl http://127.0.0.1:5050/api/v1/datasets/privesc"},
    {"method": "POST",   "path": "/api/v1/datasets/<name>/load", "cat": "datasets",
     "short": "Carga un dataset en la DB",
     "long":  "Lee el archivo JSON del dataset desde data/ y lo deja cargado en la DB en memoria. Después de esto, los endpoints de commands, shells, search, etc. funcionan sobre esos datos. Si ya estaba cargado, avisa con 200 en vez de crearlo de nuevo.",
     "params": [{"name": "name", "in": "path", "required": True, "type": "string", "desc": "Nombre del dataset a cargar"}],
     "example": "curl -X POST http://127.0.0.1:5050/api/v1/datasets/privesc/load"},
    {"method": "DELETE", "path": "/api/v1/datasets/<name>","cat": "datasets",
     "short": "Descarga un dataset de la DB",
     "long":  "Saca un dataset de la DB en memoria. El archivo JSON en data/ no se toca. Después de esto, los endpoints de commands/shells que dependan de ese dataset dejan de tener resultados.",
     "params": [{"name": "name", "in": "path", "required": True, "type": "string", "desc": "Nombre del dataset a descargar"}],
     "example": "curl -X DELETE http://127.0.0.1:5050/api/v1/datasets/privesc"},

    # ---- Commands ----
    {"method": "GET",    "path": "/api/v1/commands",       "cat": "commands",
     "short": "Busca comandos con filtros combinables",
     "long":  "Busca comandos en los datasets cargados. Todos los filtros son opcionales y se pueden combinar. El parámetro limit corta la cantidad de resultados.",
     "params": [
         {"name": "cat",      "in": "query", "required": False, "type": "string", "desc": "Categoría exacta (suid, sudo, cron, kernel, etc.)"},
         {"name": "q",        "in": "query", "required": False, "type": "string", "desc": "Texto libre sobre cmd o desc (case-insensitive)"},
         {"name": "severity", "in": "query", "required": False, "type": "string", "desc": "Severidad exacta (info, low, medium, high, critical)"},
         {"name": "dataset",  "in": "query", "required": False, "type": "string", "desc": "Filtrar por dataset"},
         {"name": "limit",    "in": "query", "required": False, "type": "int",    "desc": "Máximo de resultados (default 100)"},
     ],
     "example": "curl 'http://127.0.0.1:5050/api/v1/commands?cat=suid&severity=critical'"},
    {"method": "GET",    "path": "/api/v1/commands/<id>", "cat": "commands",
     "short": "Detalle de un comando por ID",
     "long":  "Devuelve el detalle completo de un comando. El ID tiene formato 'dataset/categoria/indice', por ejemplo 'privesc/suid/0'. Sirve para inspeccionar un resultado puntual después de un listado.",
     "params": [{"name": "id", "in": "path", "required": True, "type": "string", "desc": "ID con formato dataset/categoria/indice"}],
     "example": "curl http://127.0.0.1:5050/api/v1/commands/privesc/suid/0"},

    # ---- Shells ----
    {"method": "GET",    "path": "/api/v1/shells",         "cat": "shells",
     "short": "Lista todos los reverse shells cargados",
     "long":  "Devuelve el diccionario completo de reverse shells presentes en los datasets cargados (actualmente viven en el dataset privesc). Cada shell tiene un id, payload y descripción.",
     "params": [], "example": "curl http://127.0.0.1:5050/api/v1/shells"},
    {"method": "GET",    "path": "/api/v1/shells/<id>",   "cat": "shells",
     "short": "Detalle de un reverse shell",
     "long":  "Devuelve el detalle completo de un shell específico por su id (bash_tcp, python3, nc, perl, php, etc.).",
     "params": [{"name": "id", "in": "path", "required": True, "type": "string", "desc": "ID del shell (bash_tcp, python3, nc...)"}],
     "example": "curl http://127.0.0.1:5050/api/v1/shells/python3"},

    # ---- DB / estado ----
    {"method": "GET",    "path": "/api/v1/db",             "cat": "estado",
     "short": "Estado completo de la DB",
     "long":  "Resumen del estado actual: qué datasets hay cargados, total de comandos, total de categorías, cantidad de queries, cambios de estado, hora de arranque.",
     "params": [], "example": "curl http://127.0.0.1:5050/api/v1/db"},
    {"method": "DELETE", "path": "/api/v1/db",             "cat": "estado",
     "short": "Vacía la DB por completo",
     "long":  "Saca TODOS los datasets de la DB. Equivale a un 'reset' total. Los archivos JSON en data/ no se modifican, solo se olvida lo que estaba en memoria.",
     "params": [], "example": "curl -X DELETE http://127.0.0.1:5050/api/v1/db"},
    {"method": "GET",    "path": "/api/v1/queries",        "cat": "estado",
     "short": "Log de las últimas queries",
     "long":  "Devuelve el log de las últimas 50 queries recibidas con método, path y timestamp. Sirve para análisis Blue Team: ver qué pidió cada cliente.",
     "params": [], "example": "curl http://127.0.0.1:5050/api/v1/queries"},
    {"method": "GET",    "path": "/api/v1/stats",          "cat": "estado",
     "short": "Estadísticas agregadas del lab",
     "long":  "Conteo agregado de comandos por categoría y por severidad, y total de queries registradas.",
     "params": [], "example": "curl http://127.0.0.1:5050/api/v1/stats"},
]

# Si querés sumar más datasets, agregalos al directorio data/

# ---------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------
def log_query(method, path):
    DB["queries"].append({
        "method": method,
        "path": path,
        "ts": utc_now_iso()
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
    """Página principal: home con los 3 botones (Cargar / Consola / Ayuda)."""
    return send_from_directory(BASE_DIR, "home.html")

@app.route("/consola")
def consola():
    """La consola de comandos (antes era la página principal)."""
    return send_from_directory(BASE_DIR, "static_index.html")

@app.route("/cargar")
def cargar_page():
    """Página para cargar datasets con botones (POST visual)."""
    return send_from_directory(BASE_DIR, "cargar.html")

@app.route("/modo1")
def modo1_page():
    """Modo 1: DB pre-cargada al arrancar (necesita --autoload al iniciar)."""
    return send_from_directory(BASE_DIR, "modo1.html")

@app.route("/modo3")
def modo3_page():
    """Modo 3: juego random por tema (single-player). Placeholder por ahora."""
    return send_from_directory(BASE_DIR, "modo3.html")

@app.route("/modo4")
def modo4_page():
    """Modo 4: 1 vs 1 (multijugador). Placeholder por ahora."""
    return send_from_directory(BASE_DIR, "modo4.html")

@app.route("/standalone")
@app.route("/option1")
def standalone_page():
    """Sirve la opción 1 (standalone HTML) directamente desde el Flask,
    así se puede acceder a http://host:port/standalone sin abrir file://.
    El archivo option1/api-lab.html también sigue siendo standalone
    (se puede abrir con doble click y funciona solo)."""
    opt1 = BASE_DIR.parent / "option1" / "api-lab.html"
    if not opt1.exists():
        return jsonify({"error": "option1/api-lab.html no encontrado"}), 404
    return send_from_directory(str(opt1.parent), opt1.name)

@app.route("/api/v1/help")
def help():
    log_query("GET", "/api/v1/help")
    # Agrupar por categoría para que la respuesta sea más fácil de leer
    by_cat = {}
    for ep in ENDPOINTS_CATALOG:
        by_cat.setdefault(ep["cat"], []).append({
            "method":  ep["method"],
            "path":    ep["path"],
            "short":   ep["short"],
            "long":    ep["long"],
            "params":  ep["params"],
            "example": ep["example"]
        })
    return jsonify({
        "lab": "API Lab — Pentesting & Linux",
        "version": "1.1.0",
        "manual_html": "/manual",
        "help_texto_plano": "/api/v1/help.txt",
        "categorias": by_cat,
        "endpoints_count": len(ENDPOINTS_CATALOG)
    })

@app.route("/api/v1/help.txt")
def help_txt():
    """Ayuda completa en texto plano, ideal para leer en la terminal."""
    log_query("GET", "/api/v1/help.txt")
    lines = []
    lines.append("=" * 72)
    lines.append("API LAB — Pentesting & Linux  (v1.1.0)")
    lines.append("=" * 72)
    lines.append("")
    lines.append("Manual HTML completo:    http://127.0.0.1:5050/manual")
    lines.append("Esta ayuda (formato JSON): http://127.0.0.1:5050/api/v1/help")
    lines.append("")
    # Agrupar y mostrar por categoría
    cats = {}
    for ep in ENDPOINTS_CATALOG:
        cats.setdefault(ep["cat"], []).append(ep)
    for cat, eps in cats.items():
        lines.append("-" * 72)
        lines.append(f"CATEGORÍA: {cat.upper()}")
        lines.append("-" * 72)
        for ep in eps:
            lines.append("")
            lines.append(f"  {ep['method']:6s}  {ep['path']}")
            lines.append(f"  {ep['short']}")
            lines.append("")
            # wrap descripción larga a 70 chars
            for paragraph in ep["long"].split("\n"):
                lines.append("    " + paragraph.strip())
            if ep["params"]:
                lines.append("")
                lines.append("    Parámetros:")
                for p in ep["params"]:
                    req = "obligatorio" if p.get("required") else "opcional"
                    lines.append(f"      - {p['name']} ({p['type']}, {req}, en {p['in']}): {p['desc']}")
            lines.append("")
            lines.append(f"    Ejemplo: {ep['example']}")
            lines.append("")
    lines.append("=" * 72)
    lines.append("Para más detalles y paso a paso, abrí el manual HTML:")
    lines.append("    http://127.0.0.1:5050/manual")
    lines.append("=" * 72)
    response = app.response_class("\n".join(lines), mimetype="text/plain; charset=utf-8")
    return response

@app.route("/manual")
@app.route("/manual.html")
def manual():
    """Sirve el manual HTML independiente que vive en docs/."""
    manual_path = DOCS_DIR / "MANUAL.html"
    if not manual_path.exists():
        return jsonify({"error": "Manual no encontrado", "path_esperado": str(manual_path)}), 404
    return send_from_directory(str(manual_path.parent), manual_path.name)

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
    payload["loaded_at"] = utc_now_iso()
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
    DB["history"].append({"action": "unload", "dataset": name, "ts": utc_now_iso()})
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
    DB["history"].append({"action": "flush", "ts": utc_now_iso()})
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
# DISCOVERY — endpoints para reconocimiento de la API (pentest recon)
# ---------------------------------------------------------------------
@app.route("/api/v1/discovery", methods=["GET", "OPTIONS"])
def discovery():
    log_query(request.method, "/api/v1/discovery")
    info = {
        "lab": "API Lab — Pentesting & Linux",
        "version": "1.1.0",
        "api_root": "/api/v1",
        "docs": "/api/v1/help",
        "fingerprint": "/api/v1/fingerprint",
        "routes": "/api/v1/routes",
        "datasets_available": [k for k, v in DATASETS.items() if v is not None],
        "datasets_loaded": list(DB["loaded"].keys()),
        "endpoints_count": len(list(app.url_map.iter_rules())),
        "started_at": DB["started_at"]
    }
    if request.method == "OPTIONS":
        # CORS-style: anuncia métodos permitidos
        resp = jsonify(info)
        resp.headers["Allow"] = "GET, OPTIONS"
        resp.headers["X-Discovery-Methods"] = "GET, OPTIONS"
        return resp
    return jsonify(info)

@app.route("/api/v1/fingerprint", methods=["GET"])
def fingerprint():
    log_query("GET", "/api/v1/fingerprint")
    from importlib.metadata import version as pkg_version
    return jsonify({
        "server": "Werkzeug (Flask dev server)",
        "framework": "Flask",
        "framework_version": pkg_version("flask"),
        "python_version": sys.version.split()[0],
        "content_type": "application/json",
        "encoding": "utf-8",
        "cors": False,
        "auth_required": False,
        "rate_limit": False,
        "debug_mode": app.debug
    })

@app.route("/api/v1/routes", methods=["GET"])
def list_routes():
    log_query("GET", "/api/v1/routes")
    routes = []
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
        routes.append({
            "rule": rule.rule,
            "methods": sorted(m for m in rule.methods if m not in ("HEAD", "OPTIONS")),
            "endpoint": rule.endpoint
        })
    return jsonify({"count": len(routes), "routes": routes})

@app.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "uptime_since": DB["started_at"],
        "datasets_available": sum(1 for v in DATASETS.values() if v is not None),
        "datasets_loaded": len(DB["loaded"]),
        "ts": utc_now_iso()
    })

@app.route("/api/v1/severities", methods=["GET"])
def list_severities():
    log_query("GET", "/api/v1/severities")
    sev_counts = {}
    for ds in DB["loaded"].values():
        for cat in (ds.get("categories") or {}).values():
            sev = cat.get("severity", "unknown")
            sev_counts[sev] = sev_counts.get(sev, 0) + len(cat.get("commands", []))
    return jsonify({
        "count": len(sev_counts),
        "severities": sev_counts,
        "hint": "Cargá un dataset primero: POST /api/v1/datasets/privesc/load"
    })

@app.route("/api/v1/categories", methods=["GET"])
def list_categories():
    log_query("GET", "/api/v1/categories")
    items = []
    for ds_name, ds in DB["loaded"].items():
        for cat_key, cat in (ds.get("categories") or {}).items():
            items.append({
                "dataset": ds_name,
                "key": cat_key,
                "title": cat.get("title"),
                "severity": cat.get("severity"),
                "commands": len(cat.get("commands", []))
            })
    return jsonify({
        "count": len(items),
        "categories": items,
        "hint": "Cargá un dataset primero: POST /api/v1/datasets/privesc/load"
    })

@app.route("/api/v1/schemas/<name>", methods=["GET"])
def dataset_schema(name):
    log_query("GET", f"/api/v1/schemas/{name}")
    ds = None
    source = None
    if name in DB["loaded"]:
        ds = DB["loaded"][name]
        source = "db"
    elif name in DATASETS and DATASETS[name] is not None:
        ds = DATASETS[name]
        source = "remote"
    if ds is None:
        return jsonify({"error": f"Dataset '{name}' no existe", "available": list(DATASETS.keys())}), 404
    cats = ds.get("categories") or {}
    sample_cmd = None
    if cats:
        first_cat = next(iter(cats.values()))
        cmds = first_cat.get("commands") or []
        if cmds:
            sample_cmd = cmds[0]
    shells_keys = list((ds.get("shells") or {}).keys())
    return jsonify({
        "name": ds.get("name"),
        "source": source,
        "description": ds.get("description"),
        "structure": {
            "name": "string",
            "description": "string",
            "categories": {
                "<key>": {
                    "title": "string",
                    "severity": "string (info|low|medium|high|critical)",
                    "commands": [
                        {
                            "cmd": "string",
                            "desc": "string"
                        }
                    ]
                }
            },
            "shells": {
                "<id>": {
                    "payload": "string",
                    "desc": "string"
                }
            },
            "loaded_at": "string (ISO-8601 UTC) — sólo si viene de db"
        },
        "categories": list(cats.keys()),
        "commands_count": count_commands(ds),
        "categories_count": count_categories(ds),
        "shells_keys": shells_keys,
        "sample_command": sample_cmd
    })

@app.route("/api/v1/search", methods=["GET"])
def global_search():
    log_query("GET", "/api/v1/search")
    if not DB["loaded"]:
        return jsonify({
            "error": "DB vacía",
            "hint": "Cargá un dataset primero: POST /api/v1/datasets/privesc/load"
        }), 503
    q = request.args.get("q", "").lower().strip()
    if not q:
        return jsonify({"error": "Parámetro 'q' requerido", "example": "/api/v1/search?q=python"}), 400
    limit = int(request.args.get("limit", 50))
    results = []
    for ds_name, ds in DB["loaded"].items():
        for cat_key, cat_data in (ds.get("categories") or {}).items():
            for idx, cmd in enumerate(cat_data.get("commands", [])):
                if q in cmd.get("cmd", "").lower() or q in cmd.get("desc", "").lower():
                    results.append({
                        "type": "command",
                        "id": f"{ds_name}/{cat_key}/{idx}",
                        "dataset": ds_name,
                        "category": cat_key,
                        "severity": cat_data.get("severity"),
                        "cmd": cmd.get("cmd"),
                        "desc": cmd.get("desc")
                    })
        for shell_id, shell_data in (ds.get("shells") or {}).items():
            if q in shell_id.lower() or q in str(shell_data).lower():
                results.append({
                    "type": "shell",
                    "id": shell_id,
                    "dataset": ds_name,
                    "payload": shell_data.get("payload"),
                    "desc": shell_data.get("desc")
                })
    return jsonify({
        "q": q,
        "count": len(results),
        "returned": min(limit, len(results)),
        "results": results[:limit]
    })

@app.route("/api/v1/random", methods=["GET"])
def random_command():
    log_query("GET", "/api/v1/random")
    if not DB["loaded"]:
        return jsonify({
            "error": "DB vacía",
            "hint": "Cargá un dataset primero: POST /api/v1/datasets/privesc/load"
        }), 503
    dataset = request.args.get("dataset")
    severity = request.args.get("severity")
    pool = []
    for ds_name, ds in DB["loaded"].items():
        if dataset and dataset != ds_name:
            continue
        for cat_key, cat_data in (ds.get("categories") or {}).items():
            if severity and cat_data.get("severity") != severity:
                continue
            for idx, cmd in enumerate(cat_data.get("commands", [])):
                pool.append({
                    "id": f"{ds_name}/{cat_key}/{idx}",
                    "dataset": ds_name,
                    "category": cat_key,
                    "category_title": cat_data.get("title"),
                    "severity": cat_data.get("severity"),
                    "cmd": cmd.get("cmd"),
                    "desc": cmd.get("desc")
                })
    if not pool:
        return jsonify({"error": "Sin resultados con esos filtros"}), 404
    return jsonify(random.choice(pool))

# ---------------------------------------------------------------------
# CLIENTES — endpoints dedicados para data/clientes.json
#   Este dataset tiene un formato distinto (schema + items, no categories).
#   Los endpoints leen el archivo directamente del disco, no necesitan
#   "load" en memoria. La estructura es plana por item.
# ---------------------------------------------------------------------
def _load_clientes():
    """Lee data/clientes.json del disco. Devuelve el dict o None si no existe."""
    path = DATA_DIR / "clientes.json"
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def _cliente_to_dict(item):
    """Normaliza un item de clientes para output."""
    return {
        "id":            item.get("id"),
        "ID":            item.get("ID"),
        "nombres":       item.get("nombres"),
        "apellidos":     item.get("apellidos"),
        "DOC. tipo":     item.get("DOC. tipo"),
        "DNI":           item.get("DNI"),
        "CUIT":          item.get("CUIT"),
        "Registro civil":item.get("Registro civil"),
        "Domicilio":     item.get("Domicilio"),
        "Domicilios":    item.get("Domicilios"),
        "Test1":         item.get("Test1"),
        "Test2":         item.get("Test2"),
        "Registro conducir": item.get("Registro conducir"),
        "tipo de sangre":item.get("tipo de sangre"),
        "creditos":      item.get("creditos"),
        "apto":          item.get("apto"),
        "no apto":       item.get("no apto"),
    }

@app.route("/api/v1/clientes", methods=["GET"])
def list_clientes():
    """Lista todos los clientes. Soporta ?limit=, ?offset=, ?apto=true|false."""
    log_query("GET", "/api/v1/clientes")
    data = _load_clientes()
    if data is None:
        return jsonify({"error": "data/clientes.json no existe"}), 404
    items = data.get("items", [])
    # filtros
    apto = request.args.get("apto")
    if apto is not None:
        if apto.lower() == "true":
            items = [c for c in items if c.get("apto") is True]
        elif apto.lower() == "false":
            items = [c for c in items if c.get("apto") is False]
    try:
        limit = int(request.args.get("limit", 100))
    except ValueError:
        limit = 100
    try:
        offset = int(request.args.get("offset", 0))
    except ValueError:
        offset = 0
    total = len(items)
    page = items[offset:offset + limit]
    return jsonify({
        "name": data.get("name"),
        "description": data.get("description"),
        "schema": data.get("schema"),
        "count": total,
        "returned": len(page),
        "offset": offset,
        "limit": limit,
        "items": [_cliente_to_dict(c) for c in page]
    })

@app.route("/api/v1/clientes/<int:cli_id>", methods=["GET"])
def get_cliente(cli_id):
    """Detalle de un cliente por su id numérico."""
    log_query("GET", f"/api/v1/clientes/{cli_id}")
    data = _load_clientes()
    if data is None:
        return jsonify({"error": "data/clientes.json no existe"}), 404
    for c in data.get("items", []):
        if c.get("id") == cli_id:
            return jsonify(_cliente_to_dict(c))
    return jsonify({"error": f"Cliente con id={cli_id} no encontrado", "available_ids": [c.get("id") for c in data.get("items", [])]}), 404

@app.route("/api/v1/clientes/search", methods=["GET"])
def search_clientes():
    """Búsqueda full-text sobre los campos string de los clientes."""
    log_query("GET", "/api/v1/clientes/search")
    data = _load_clientes()
    if data is None:
        return jsonify({"error": "data/clientes.json no existe"}), 404
    q = request.args.get("q", "").lower().strip()
    if not q:
        return jsonify({"error": "Parámetro 'q' requerido", "example": "/api/v1/clientes/search?q=alberto"}), 400
    campos_str = ["ID", "nombres", "apellidos", "DOC. tipo", "DNI", "CUIT",
                  "Registro civil", "Domicilio", "Registro conducir", "tipo de sangre"]
    resultados = []
    for c in data.get("items", []):
        for campo in campos_str:
            val = c.get(campo)
            if val and q in str(val).lower():
                resultados.append(_cliente_to_dict(c))
                break
        else:
            # también buscar en el array de domicilios
            doms = c.get("Domicilios") or []
            if any(q in str(d).lower() for d in doms):
                resultados.append(_cliente_to_dict(c))
    return jsonify({
        "q": q,
        "count": len(resultados),
        "results": resultados
    })

# ---------------------------------------------------------------------
# STATIC
# ---------------------------------------------------------------------
@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(BASE_DIR, filename)

def _do_load(name):
    """Carga un dataset a la DB sin pasar por HTTP. Usado por --autoload y endpoints."""
    if name not in DATASETS or DATASETS[name] is None:
        return False, f"Dataset '{name}' no existe"
    if name in DB["loaded"]:
        return True, f"ya estaba cargado"
    payload = json.loads(json.dumps(DATASETS[name]))
    payload["loaded_at"] = utc_now_iso()
    DB["loaded"][name] = payload
    DB["history"].append({"action": "load", "dataset": name, "ts": payload["loaded_at"], "source": "autoload"})
    return True, f"cargado ({count_commands(payload)} comandos)"


# ---------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------
if __name__ == "__main__":
    port = 5050
    host = "127.0.0.1"
    autoload = []
    if "--host" in sys.argv:
        i = sys.argv.index("--host")
        host = sys.argv[i + 1] if i + 1 < len(sys.argv) else "0.0.0.0"
    if "--port" in sys.argv:
        i = sys.argv.index("--port")
        port = int(sys.argv[i + 1])
    if "--autoload" in sys.argv:
        i = sys.argv.index("--autoload")
        autoload = [s.strip() for s in sys.argv[i + 1].split(",") if s.strip()] if i + 1 < len(sys.argv) else []

    # autoload: cargar datasets ANTES de levantar el server
    if autoload:
        print(f"⚙  --autoload: {autoload}")
        for name in autoload:
            ok, msg = _do_load(name)
            mark = "✓" if ok else "✗"
            print(f"   {mark} {name}: {msg}")

    print(f"""
╔════════════════════════════════════════════════════════════╗
║           API LAB — Pentesting & Linux                     ║
║                                                            ║
║   Servidor:  http://{host}:{port}                           ║
║   Datos:     {len([v for v in DATASETS.values() if v])} datasets disponibles                ║
║   DB ahora:  {len(DB["loaded"])} cargados · {sum(count_commands(d) for d in DB["loaded"].values())} comandos                                ║
║                                                            ║
║   Endpoints clave:                                         ║
║     GET  /api/v1/help                                       ║
║     GET  /api/v1/datasets                                   ║
║     POST /api/v1/datasets/privesc/load                      ║
║     GET  /api/v1/commands?cat=suid&severity=critical        ║
║     GET  /api/v1/shells                                     ║
║                                                            ║
║   Modos:                                                   ║
║     /         → home con selector de modo                  ║
║     /modo1    → DB pre-cargada (necesita --autoload)       ║
║     /consola  → modo 2: manual                             ║
║     /cargar   → botones CARGAR / VACIAR                    ║
║     /modo3    → juego random por tema (próximamente)       ║
║     /modo4    → 1 vs 1 (próximamente)                      ║
║                                                            ║
║   Ctrl+C para detener.                                     ║
╚════════════════════════════════════════════════════════════╝
""")
    app.run(host=host, port=port, debug=False)