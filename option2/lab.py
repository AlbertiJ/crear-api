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
# ESTADO DEL JUEGO (modos 3 y 4)
# ---------------------------------------------------------------------
#   None             → no hay juego activo (modo 1 / 2 normal)
#   {"mode": 3|4,
#    "themes": [...],          # temas seleccionados
#    "total_items": int,       # cantidad total de items en juego
#    "item_ids": set(),        # todos los IDs que deberían descubrirse
#    "started_at": iso,
#    "ends_at":   iso}         # deadline (1h en modo 4)
GAME = None
DISCOVERED = set()  # IDs que ya descubrió el jugador

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
# TEMAS — datasets seed para modo 3 (juego random)
# ---------------------------------------------------------------------
# Cada theme = { name, icon, description, items: [ {id, ...}, ... ] }
# Los items se cargan en memoria pero NO se exponen como 'datasets'
# hasta que el jugador elija temas y arme la mezcla (modo 3).
THEMES = {}
for _theme_file in ["musica.json", "peliculas.json", "personajes.json"]:
    _data = load_dataset_file("themes/" + _theme_file)
    if _data:
        _key = _theme_file.replace(".json", "")  # "musica", "peliculas", "personajes"
        THEMES[_key] = _data

# Mapeo de theme_id → "categoría" que verá el jugador en /api/v1/commands?cat=
# (musica → "musica", peliculas → "peliculas", etc)
THEME_CATEGORY = {t: t for t in THEMES}

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

    cat = request.args.get("cat")
    q = request.args.get("q", "").lower()
    severity = request.args.get("severity")
    dataset = request.args.get("dataset")
    limit = int(request.args.get("limit", 100))

    results = []
    # MODO 4 cross-over: si hay ?pid= y la sala está en playing, devolver DB del RIVAL
    mode4_pid = request.args.get("pid")
    mode4_room = None
    mode4_opp_db = None
    if mode4_pid:
        room_code = PLAYER_ROOM.get(mode4_pid)
        if room_code:
            r = ROOMS.get(room_code)
            if r and r["phase"] == "playing" and mode4_pid in r["players"]:
                mode4_room = r
                cat_key, opp_items = _get_opponent_db_for_player(r["code"], mode4_pid)
                if opp_items is not None:
                    mode4_opp_db = {"rival": {"categories": {cat_key: {
                        "title": "DB del rival",
                        "severity": "info",
                        "commands": opp_items,
                    }}}}
    if mode4_opp_db:
        dss = mode4_opp_db.items()
    else:
        if not DB["loaded"]:
            return jsonify({
                "error": "DB vacía",
                "hint": "Cargá un dataset primero: POST /api/v1/datasets/privesc/load"
            }), 503
        dss = DB["loaded"].items()
    for ds_name, ds in dss:
        if dataset and dataset != ds_name:
            continue
        for cat_key, cat_data in (ds.get("categories") or {}).items():
            if cat and cat != cat_key:
                continue
            if severity and cat_data.get("severity") != severity:
                continue
            for idx, cmd in enumerate(cat_data.get("commands", [])):
                # q matchea contra cmd, desc Y _search (todos los campos del item de tema)
                if q:
                    haystack = (
                        cmd.get("cmd", "") + " " +
                        cmd.get("desc", "") + " " +
                        cmd.get("_search", "")
                    ).lower()
                    if q not in haystack:
                        continue
                # id real si existe (temas), sino fallback por índice
                cmd_id = cmd.get("id") or f"{ds_name}/{cat_key}/{idx}"
                results.append({
                    "id": cmd_id,
                    "dataset": ds_name,
                    "category": cat_key,
                    "category_title": cat_data.get("title"),
                    "severity": cat_data.get("severity"),
                    "theme": cat_data.get("theme"),
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
    # MODO 4 cross-over: si hay ?pid= y la sala está en playing, buscar en DB del RIVAL
    mode4_pid = request.args.get("pid")
    if mode4_pid:
        room_code = PLAYER_ROOM.get(mode4_pid)
        if room_code:
            r = ROOMS.get(room_code)
            if r and r["phase"] == "playing" and mode4_pid in r["players"]:
                cat_key, opp_items = _get_opponent_db_for_player(r["code"], mode4_pid)
                if opp_items is not None:
                    for cmd in opp_items:
                        if cmd.get("id") == cmd_id:
                            return jsonify({
                                "id": cmd_id,
                                "dataset": "rival",
                                "category": cat_key,
                                "category_title": "DB del rival",
                                "severity": "info",
                                "cmd": cmd.get("cmd"),
                                "desc": cmd.get("desc"),
                                "raw": cmd.get("_raw"),
                            })
                    return jsonify({"error": f"Item '{cmd_id}' no encontrado en la DB del rival"}), 404
    # Soporta dos formatos:
    #   A) "mus_001" / "pel_002" — id real de un tema (modo 3)
    #   B) "privesc/suid/3"     — formato viejo dataset/cat/index (modo 2)
    if "/" in cmd_id:
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
    # formato A — id de tema (mus_001, pel_002, etc.)
    for ds_name, ds in DB["loaded"].items():
        for cat_key, cat in (ds.get("categories") or {}).items():
            for cmd in cat.get("commands", []):
                if cmd.get("id") == cmd_id:
                    return jsonify({
                        "id": cmd_id,
                        "dataset": ds_name,
                        "category": cat_key,
                        "category_title": cat.get("title"),
                        "severity": cat.get("severity"),
                        "theme": cat.get("theme"),
                        "cmd": cmd.get("cmd"),
                        "desc": cmd.get("desc"),
                        "raw": cmd.get("_raw"),
                    })
    return jsonify({"error": f"Item '{cmd_id}' no encontrado"}), 404

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
    # intentar adivinar la IP del server desde el request (LAN)
    server_ip = request.host.split(":")[0] if request.host else "127.0.0.1"
    return jsonify({
        "status": "ok",
        "uptime_since": DB["started_at"],
        "datasets_available": sum(1 for v in DATASETS.values() if v is not None),
        "datasets_loaded": len(DB["loaded"]),
        "server_ip": server_ip,
        "server_url": request.host_url.rstrip("/"),
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
    q = request.args.get("q", "").lower().strip()
    if not q:
        return jsonify({"error": "Parámetro 'q' requerido", "example": "/api/v1/search?q=python"}), 400
    limit = int(request.args.get("limit", 50))
    results = []
    # MODO 4 cross-over (chequear ANTES de DB vacía)
    mode4_pid = request.args.get("pid")
    mode4_opp_items = None
    if mode4_pid:
        room_code = PLAYER_ROOM.get(mode4_pid)
        if room_code:
            r = ROOMS.get(room_code)
            if r and r["phase"] == "playing" and mode4_pid in r["players"]:
                cat_key, opp_items = _get_opponent_db_for_player(r["code"], mode4_pid)
                if opp_items is not None:
                    mode4_opp_items = (cat_key, opp_items)
    if mode4_opp_items:
        cat_key, opp_items = mode4_opp_items
        for cmd in opp_items:
            haystack = (
                cmd.get("cmd", "") + " " +
                cmd.get("desc", "") + " " +
                cmd.get("_search", "")
            ).lower()
            if q in haystack:
                results.append({
                    "type": "command",
                    "id": cmd.get("id"),
                    "dataset": "rival",
                    "category": cat_key,
                    "category_title": "DB del rival",
                    "severity": "info",
                    "cmd": cmd.get("cmd"),
                    "desc": cmd.get("desc")
                })
    else:
        if not DB["loaded"]:
            return jsonify({
                "error": "DB vacía",
                "hint": "Cargá un dataset primero: POST /api/v1/datasets/privesc/load"
            }), 503
        for ds_name, ds in DB["loaded"].items():
            for cat_key, cat_data in (ds.get("categories") or {}).items():
                for idx, cmd in enumerate(cat_data.get("commands", [])):
                    haystack = (
                        cmd.get("cmd", "") + " " +
                        cmd.get("desc", "") + " " +
                        cmd.get("_search", "")
                    ).lower()
                    if q in haystack:
                        cmd_id = cmd.get("id") or f"{ds_name}/{cat_key}/{idx}"
                        results.append({
                            "type": "command",
                            "id": cmd_id,
                            "dataset": ds_name,
                            "category": cat_key,
                            "category_title": cat_data.get("title"),
                            "severity": cat_data.get("severity"),
                            "theme": cat_data.get("theme"),
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
# HARDENING — seguridad básica para cuando se expone en LAN
# ---------------------------------------------------------------------
# Whitelist de redes privadas (loopback, RFC 1918). El server solo
# acepta requests de estas redes cuando se expone con --host != 127.0.0.1.
# Requests desde internet (IP pública) → 403.
def _ip_is_private(ip):
    """Devuelve True si la IP es loopback, privada o link-local."""
    if not ip:
        return False
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_loopback or
            addr.is_private or        # 10.x, 172.16-31.x, 192.168.x
            addr.is_link_local        # 169.254.x
        )
    except ValueError:
        return False

# Rate limit básico: max N salas por IP por ventana de tiempo
ROOM_CREATE_HISTORY = []  # [(ip, ts), ...]
ROOM_CREATE_WINDOW = 60   # segundos
ROOM_CREATE_MAX = 5       # max salas por ventana

def _rate_limit_ok(ip):
    """Devuelve True si la IP puede crear una sala más."""
    import time as _t
    now = _t.time()
    # limpiar viejas
    while ROOM_CREATE_HISTORY and ROOM_CREATE_HISTORY[0][1] < now - ROOM_CREATE_WINDOW:
        ROOM_CREATE_HISTORY.pop(0)
    # contar las del IP
    count = sum(1 for (i, t) in ROOM_CREATE_HISTORY if i == ip)
    if count >= ROOM_CREATE_MAX:
        return False
    ROOM_CREATE_HISTORY.append((ip, now))
    return True

# Modo público: si el server está expuesto en LAN (no loopback), aplicar
# whitelist de IPs privadas + rate limit.
PUBLIC_MODE = False  # se setea en __main__


@app.before_request
def security_guard():
    """Filtra requests antes de llegar a las vistas."""
    # siempre permitir health (chequeo del frontend) y discovery
    if request.path in ("/api/v1/health", "/api/v1/discovery"):
        return None
    # si está en modo público, chequear IP
    if PUBLIC_MODE:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        ip = ip.split(",")[0].strip()
        if not _ip_is_private(ip):
            DB["history"].append({
                "action": "blocked_public_ip",
                "ts": utc_now_iso(),
                "ip": ip,
                "path": request.path,
            })
            return jsonify({
                "error": "Acceso bloqueado",
                "reason": "Este server está configurado para LAN. Solo IPs privadas son aceptadas.",
                "your_ip": ip,
                "hint": "Si querés exponer a internet, usá un reverse proxy con autenticación.",
            }), 403
    return None


# ---------------------------------------------------------------------
# MODO 4 — 1 vs 1 MULTIJUGADOR (salas en LAN)
# ---------------------------------------------------------------------
# Cada sala tiene:
#   {
#     "code": "K7MP",                # 4 chars alfanuméricos
#     "created_at": iso,
#     "phase": "waiting" | "loading" | "ready" | "playing" | "finished",
#     "host_id": "abc",              # id del jugador que creó la sala
#     "players": {
#       "abc": {
#         "name": "Juan",
#         "joined_at": iso,
#         "theme": None,             # tema elegido (None hasta que elija)
#         "ready": False,            # apretó ✓ LISTO
#         "db": None,                # {categories: {...}} con 15 items random
#         "discovered": set(),       # IDs que descubrió
#       },
#       ...
#     },
#     "started_at": None,            # cuando arrancó el timer 1h
#     "ends_at":   None,            # +1h desde started_at
#     "winner_id": None,            # id del ganador (None si empate o sin finish)
#     "items_per_player": 15,
#     "game_duration_sec": 3600,    # 1 hora
#   }
#
# Cross-over: cuando phase=playing, las queries de un jugador devuelven
# los items de la DB del RIVAL, y el discovered se trackea por jugador.
ROOMS = {}  # code -> Room
# Mapping pid -> code (para que queries con ?pid= encuentren su room sin ambigüedad)
PLAYER_ROOM = {}

def _gen_room_code():
    """Genera un código de 4 chars (letras + números, sin 0/O/1/I para confusión)."""
    import random as _r
    _r.seed()
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # sin 0/O/1/I
    return "".join(_r.choice(chars) for _ in range(4))


def _new_player():
    """Genera un player_id único (8 chars)."""
    import random as _r
    _r.seed()
    return "p_" + "".join(_r.choice("abcdef0123456789") for _ in range(8))


def _public_room(room, viewer_id=None):
    """Devuelve la vista pública de la sala (sin la DB del rival, etc.)."""
    out = {
        "code": room["code"],
        "phase": room["phase"],
        "items_per_player": room["items_per_player"],
        "created_at": room["created_at"],
        "started_at": room.get("started_at"),
        "ends_at":   room.get("ends_at"),
        "winner_id": room.get("winner_id"),
        "items_count": room["items_per_player"],  # total que tiene que descubrir cada uno
        "players": {},
    }
    for pid, p in room["players"].items():
        is_self = (pid == viewer_id)
        # si es modo playing y NO es self, mostramos found pero NO los IDs
        # (para no spoilear). Si terminó, mostramos todo.
        out["players"][pid] = {
            "name": p["name"],
            "is_self": is_self,
            "theme": p.get("theme"),
            "ready": p.get("ready", False),
            "found": sum(1 for x in p.get("discovered", set())),
            "discovered_ids": list(p.get("discovered", set())) if (room["phase"] == "finished" or is_self) else [],
        }
    return out


def _room_state_for_player(code, player_id):
    """Helper: vista pública + información útil para el jugador."""
    room = ROOMS.get(code)
    if not room:
        return None, jsonify({"error": f"Sala '{code}' no existe"}), 404
    state = _public_room(room, viewer_id=player_id)
    # si está playing, devolver también: remaining_time y si terminó
    if room["phase"] == "playing" and room.get("ends_at"):
        from datetime import datetime, timezone
        try:
            ends_dt = datetime.fromisoformat(room["ends_at"].replace("Z", "+00:00"))
            now_dt = datetime.now(timezone.utc)
            remaining = max(0, int((ends_dt - now_dt).total_seconds()))
        except Exception:
            remaining = 0
        state["remaining_sec"] = remaining
        # si venció, finalizar automáticamente
        if remaining == 0 and room["phase"] == "playing":
            _finish_room_4(code, reason="time_up")
            state = _public_room(room, viewer_id=player_id)
    return room, state, 200


@app.route("/api/v1/rooms", methods=["POST"])
def create_room():
    """Crea una sala nueva (modo 4). Body: {name: 'Juan'}. Devuelve {code, player_id}."""
    global ROOMS
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "Anónimo").strip()[:20]
    if not name:
        return jsonify({"error": "Falta 'name'"}), 400
    # rate limit por IP
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if not _rate_limit_ok(ip):
        return jsonify({
            "error": f"Rate limit: máximo {ROOM_CREATE_MAX} salas por IP cada {ROOM_CREATE_WINDOW}s. Esperá un momento.",
        }), 429
    # generar código único
    for _ in range(20):
        code = _gen_room_code()
        if code not in ROOMS:
            break
    else:
        return jsonify({"error": "No se pudo generar código único"}), 500
    pid = _new_player()
    now = utc_now_iso()
    ROOMS[code] = {
        "code": code,
        "created_at": now,
        "phase": "waiting",
        "host_id": pid,
        "players": {
            pid: {
                "name": name,
                "joined_at": now,
                "theme": None,
                "ready": False,
                "db": None,
                "discovered": set(),
            }
        },
        "started_at": None,
        "ends_at": None,
        "winner_id": None,
        "items_per_player": 15,
        "game_duration_sec": 3600,
    }
    PLAYER_ROOM[pid] = code
    return jsonify({
        "code": code,
        "player_id": pid,
        "you_are_host": True,
        "join_url": f"/modo4?code={code}&pid={pid}",
    }), 201


@app.route("/api/v1/rooms/<code>/join", methods=["POST"])
def join_room(code):
    """Une a una sala existente. Body: {name: 'Pedro'}. Devuelve {player_id}."""
    global ROOMS
    room = ROOMS.get(code)
    if not room:
        return jsonify({"error": f"Sala '{code}' no existe"}), 404
    if room["phase"] != "waiting":
        return jsonify({"error": f"La sala ya está en fase '{room['phase']}', no se puede unir"}), 409
    if len(room["players"]) >= 2:
        return jsonify({"error": "Sala llena (ya hay 2 jugadores)"}), 409
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "Anónimo").strip()[:20]
    if not name:
        return jsonify({"error": "Falta 'name'"}), 400
    pid = _new_player()
    room["players"][pid] = {
        "name": name,
        "joined_at": utc_now_iso(),
        "theme": None,
        "ready": False,
        "db": None,
        "discovered": set(),
    }
    PLAYER_ROOM[pid] = code
    return jsonify({
        "code": code,
        "player_id": pid,
        "you_are_host": False,
        "join_url": f"/modo4?code={code}&pid={pid}",
    }), 201


@app.route("/api/v1/rooms/<code>", methods=["GET"])
def get_room(code):
    """Estado público de la sala. Query: ?pid=<player_id> (opcional)."""
    player_id = request.args.get("pid")
    room, state, status = _room_state_for_player(code, player_id)
    if status != 200:
        return state, status
    return jsonify(state)


@app.route("/api/v1/rooms/<code>/choose", methods=["POST"])
def room_choose_theme(code):
    """Jugador elige tema. Body: {pid, theme}. El server rellena 15 items random."""
    global ROOMS
    room = ROOMS.get(code)
    if not room:
        return jsonify({"error": f"Sala '{code}' no existe"}), 404
    body = request.get_json(silent=True) or {}
    pid = body.get("pid")
    theme = body.get("theme")
    if not pid or pid not in room["players"]:
        return jsonify({"error": "Falta 'pid' o jugador no está en la sala"}), 400
    if theme not in THEMES:
        return jsonify({"error": f"Tema '{theme}' no existe", "available": list(THEMES.keys())}), 400
    # marcar como loading y rellenar DB
    room["phase"] = "loading"
    p = room["players"][pid]
    p["theme"] = theme
    p["ready"] = False
    # generar 15 items random del pool del tema
    import random as _r
    _r.seed()
    pool = list(THEMES[theme]["items"])
    if len(pool) < room["items_per_player"]:
        return jsonify({"error": f"El tema '{theme}' tiene solo {len(pool)} items, se necesitan {room['items_per_player']}"}), 400
    chosen = _r.sample(pool, room["items_per_player"])
    # armar DB del jugador (estructura similar a themes)
    cat_key = theme
    cats = {cat_key: {
        "title": THEMES[theme]["name"],
        "severity": "info",
        "theme": theme,
        "commands": [_theme_item_to_cmd(item, theme) for item in chosen],
    }}
    p["db"] = {
        "name": f"player_{pid}",
        "description": f"DB de {p['name']} — tema {THEMES[theme]['name']}",
        "categories": cats,
        "themes_active": [theme],
    }
    return jsonify({
        "msg": f"Tema '{THEMES[theme]['name']}' elegido. {room['items_per_player']} items cargados en tu DB.",
        "theme": theme,
        "items_in_your_db": room["items_per_player"],
        "hint": "Cuando ambos hayan elegido, los dos aprietan ✓ LISTO y la PC cruza las DBs.",
    })


@app.route("/api/v1/rooms/<code>/ready", methods=["POST"])
def room_ready(code):
    """Jugador marca ✓ LISTO. Body: {pid}. Si los 2 están ready, fase pasa a 'ready'."""
    global ROOMS
    room = ROOMS.get(code)
    if not room:
        return jsonify({"error": f"Sala '{code}' no existe"}), 404
    body = request.get_json(silent=True) or {}
    pid = body.get("pid")
    if not pid or pid not in room["players"]:
        return jsonify({"error": "Falta 'pid' o jugador no está en la sala"}), 400
    p = room["players"][pid]
    if p.get("db") is None:
        return jsonify({"error": "Elegí un tema primero (POST /choose)"}), 400
    p["ready"] = True
    # si los 2 están ready
    if all(pl.get("ready") for pl in room["players"].values()):
        room["phase"] = "ready"
        return jsonify({"msg": "Ambos listos. Ahora el host puede iniciar la partida (POST /start).", "all_ready": True})
    return jsonify({"msg": f"{p['name']} listo. Esperando al rival...", "all_ready": False})


@app.route("/api/v1/rooms/<code>/start", methods=["POST"])
def room_start(code):
    """Inicia la partida (solo el host). Cross-over de DBs + timer 1h."""
    global ROOMS
    room = ROOMS.get(code)
    if not room:
        return jsonify({"error": f"Sala '{code}' no existe"}), 404
    body = request.get_json(silent=True) or {}
    pid = body.get("pid")
    if pid != room["host_id"]:
        return jsonify({"error": "Solo el host puede iniciar"}), 403
    if room["phase"] != "ready":
        return jsonify({"error": f"La sala está en fase '{room['phase']}', se necesita 'ready'"}), 409
    if not all(pl.get("ready") for pl in room["players"].values()):
        return jsonify({"error": "Falta que algún jugador apriete LISTO"}), 409
    # CROSS-OVER: arrancar timer
    now = utc_now_iso()
    from datetime import datetime, timedelta, timezone
    starts_dt = datetime.now(timezone.utc)
    ends_dt = starts_dt + timedelta(seconds=room["game_duration_sec"])
    room["phase"] = "playing"
    room["started_at"] = now
    room["ends_at"] = ends_dt.isoformat().replace("+00:00", "Z")
    # log
    room["players"][room["host_id"]]["discovered"] = set()
    for p in room["players"].values():
        if "discovered" not in p or p["discovered"] is None:
            p["discovered"] = set()
    DB["history"].append({
        "action": "room4_started",
        "ts": now,
        "code": code,
        "players": [{"name": p["name"], "theme": p["theme"]} for p in room["players"].values()],
    })
    return jsonify({
        "msg": "Partida iniciada. Timer 1h corriendo.",
        "started_at": room["started_at"],
        "ends_at": room["ends_at"],
        "duration_sec": room["game_duration_sec"],
        "your_goal": f"Descubrir los {room['items_per_player']} items que cargó tu rival.",
        "tip": "Tu consola devuelve la DB del RIVAL (no la tuya). Cada item que aparece en una respuesta se marca como descubierto en tu grilla.",
    })


@app.route("/api/v1/rooms/<code>/abandon", methods=["POST"])
def room_abandon(code):
    """Jugador se rinde. El rival gana automáticamente."""
    global ROOMS
    room = ROOMS.get(code)
    if not room:
        return jsonify({"error": f"Sala '{code}' no existe"}), 404
    body = request.get_json(silent=True) or {}
    pid = body.get("pid")
    if pid not in room["players"]:
        return jsonify({"error": "Jugador no está en la sala"}), 400
    if room["phase"] not in ("playing", "ready", "loading"):
        return jsonify({"error": f"No se puede abandonar en fase '{room['phase']}'"}), 409
    p = room["players"][pid]
    p["abandoned"] = True
    _finish_room_4(code, reason=f"{p['name']} abandonó")
    return jsonify({"msg": "Abandonaste", "summary": _public_room(room, viewer_id=pid)})


def _finish_room_4(code, reason="completed"):
    """Finaliza la partida, calcula ganador por cantidad de descubiertos."""
    room = ROOMS.get(code)
    if not room or room["phase"] == "finished":
        return
    room["phase"] = "finished"
    room["ended_at"] = utc_now_iso()
    founds = {pid: sum(1 for x in p.get("discovered", set())) for pid, p in room["players"].items()}
    if not founds:
        room["winner_id"] = None
    else:
        max_found = max(founds.values())
        winners = [pid for pid, f in founds.items() if f == max_found]
        room["winner_id"] = winners[0] if len(winners) == 1 else None  # None = empate
    DB["history"].append({
        "action": "room4_finished",
        "ts": room["ended_at"],
        "code": code,
        "reason": reason,
        "found": founds,
        "winner_id": room["winner_id"],
    })
    # limpiar mapping
    for pid in room["players"]:
        PLAYER_ROOM.pop(pid, None)


# Tracking por jugador (cross-over). Devuelve el item del RIVAL al jugador.
def _get_opponent_db_for_player(code, player_id):
    """Devuelve (cat_key, items_list) del RIVAL del player, o (None, None) si no hay rival."""
    room = ROOMS.get(code)
    if not room:
        return None, None
    others = [p for pid, p in room["players"].items() if pid != player_id]
    if not others:
        return None, None
    opp = others[0]
    if not opp.get("db"):
        return None, None
    # tomar la primera (y única) categoría
    cat_key = list(opp["db"]["categories"].keys())[0]
    items = opp["db"]["categories"][cat_key]["commands"]
    return cat_key, items


# ---------------------------------------------------------------------
# MODO 3 — JUEGO RANDOM POR TEMAS
# ---------------------------------------------------------------------
# Estructura de un item de tema (de /themes/musica.json, etc.):
#   { id, artista, cancion, album, año, genero }
#   { id, titulo, director, año, genero, pais }
#   { id, nombre, obra, tipo, creador }
#
# Para que funcione con los endpoints existentes (/commands, /commands/<id>,
# /commands?cat=X, /commands?q=...) mapeamos cada item a la forma
# { id, cmd, desc, _theme, _search } que es lo que espera /commands.
#
# - cmd   = "nombre principal" del item (artista, titulo, nombre, etc.)
# - desc  = "metadata secundaria" (resto de los campos)
# - cat   = nombre del tema (musica, peliculas, etc.) — para ?cat=musica
# - _search = concat de TODOS los campos, para búsqueda full-text
def _theme_item_to_cmd(item, theme_id):
    # Campos que son "nombre principal" según el tipo de tema
    main_keys = {
        "musica":     ["artista", "cancion"],
        "peliculas":  ["titulo", "director"],
        "personajes": ["nombre", "obra"],
        "bandas":     ["nombre", "origen"],
        "series":     ["nombre", "plataforma"],
        "paises":     ["nombre", "capital"],
    }
    ks = main_keys.get(theme_id, ["nombre", "titulo"])
    # armar el cmd
    parts = []
    for k in ks:
        v = item.get(k)
        if v: parts.append(str(v))
    cmd = " — ".join(parts) if parts else item.get("id", "?")
    # armar el desc (todo lo que no sea id ni main_keys)
    desc_parts = []
    skip = set(ks + ["id"])
    for k, v in item.items():
        if k not in skip and v not in (None, ""):
            desc_parts.append(f"{k}: {v}")
    desc = " · ".join(desc_parts)
    # texto completo para búsqueda
    search_text = " ".join(str(v) for v in item.values() if v)
    return {
        "id":      item["id"],
        "cmd":     cmd,
        "desc":    desc,
        "cat":     theme_id,
        "_theme":  theme_id,
        "_search": search_text,
        "_raw":    item,
    }


@app.route("/api/v1/themes", methods=["GET"])
def list_themes():
    """Lista los temas disponibles para modo 3 con conteo de items en el pool."""
    log_query("GET", "/api/v1/themes")
    out = []
    for tid, t in THEMES.items():
        out.append({
            "id": tid,
            "name": t.get("name", tid),
            "icon": t.get("icon", ""),
            "description": t.get("description", ""),
            "pool_size": len(t.get("items", [])),
        })
    return jsonify({
        "themes": out,
        "total": len(out),
    })


@app.route("/api/v1/themes/<theme_id>/random", methods=["POST"])
def theme_random_single(theme_id):
    """Modo 3 single-tema: agarra N items random del pool del tema y los carga."""
    log_query("POST", f"/api/v1/themes/{theme_id}/random")
    if theme_id not in THEMES:
        return jsonify({"error": f"Tema '{theme_id}' no existe", "available": list(THEMES.keys())}), 404
    body = request.get_json(silent=True) or {}
    count = int(body.get("count", 5))
    count = max(1, min(count, len(THEMES[theme_id]["items"])))
    return _start_game_mode_3([theme_id], count)


@app.route("/api/v1/themes/random", methods=["POST"])
def theme_random_multi():
    """Modo 3 multi-tema: agarra items random de varios temas y los mezcla."""
    log_query("POST", "/api/v1/themes/random")
    body = request.get_json(silent=True) or {}
    themes = body.get("themes", [])
    total = int(body.get("total", 12))
    if not themes:
        return jsonify({"error": "Falta 'themes' (lista de temas a mezclar)"}), 400
    bad = [t for t in themes if t not in THEMES]
    if bad:
        return jsonify({"error": f"Temas no válidos: {bad}", "available": list(THEMES.keys())}), 400
    return _start_game_mode_3(themes, total)


def _start_game_mode_3(themes, total):
    """Lógica común: arma la mezcla random, la carga como dataset 'themes' en DB,
    marca GAME = mode 3, resetea DISCOVERED."""
    import random as _r
    _r.seed()  # random real

    pool = []  # (theme_id, item)
    for tid in themes:
        for item in THEMES[tid]["items"]:
            pool.append((tid, item))
    # shuffle y tomar N
    _r.shuffle(pool)
    chosen = pool[:total]
    # si quieren más items que el pool, repetir/recortar
    if not chosen:
        return jsonify({"error": "Pool vacío"}), 400

    # armar estructura tipo dataset
    cats = {}
    item_ids = set()
    for tid, item in chosen:
        cmd_obj = _theme_item_to_cmd(item, tid)
        item_ids.add(cmd_obj["id"])
        # categoría con el nombre del tema (sin prefijo) para que ?cat=musica matchee
        cat_key = tid
        cats.setdefault(cat_key, {
            "title": THEMES[tid]["name"],
            "severity": "info",
            "theme": tid,
            "commands": [],
        })
        cats[cat_key]["commands"].append(cmd_obj)

    payload = {
        "name": "themes",
        "description": f"Juego random — {', '.join(themes)}",
        "categories": cats,
        "themes_active": themes,
        "loaded_at": utc_now_iso(),
    }

    # limpiar DB previa y meter la nueva
    DB["loaded"] = {}
    DB["loaded"]["themes"] = payload
    DB["history"].append({
        "action": "load",
        "dataset": "themes",
        "ts": payload["loaded_at"],
        "source": "mode3",
        "themes": themes,
        "total_items": len(chosen),
    })

    # activar juego
    global GAME, DISCOVERED
    DISCOVERED = set()
    GAME = {
        "mode": 3,
        "themes": list(themes),
        "total_items": len(chosen),
        "item_ids": item_ids,
        "started_at": utc_now_iso(),
        "ends_at": None,  # modo 3 no tiene timer
    }
    return jsonify({
        "msg": f"Juego modo 3 armado",
        "mode": 3,
        "themes": list(themes),
        "total_items": len(chosen),
        "rules": {
            "blocked_endpoints": ["/api/v1/db", "/api/v1/datasets", "/api/v1/datasets/<name>", "/api/v1/shells", "/api/v1/random", "/api/v1/categories", "/api/v1/severities"],
            "allowed_endpoints": ["/api/v1/help", "/api/v1/health", "/api/v1/discovery", "/api/v1/commands?cat=X", "/api/v1/commands/<id>", "/api/v1/commands?q=X", "/api/v1/search?q=X"],
        },
        "hint": "Empezá con GET /api/v1/commands?cat=<tema> para filtrar por tema, o probá /api/v1/search?q=<palabra>",
    }), 201


@app.route("/api/v1/game/state", methods=["GET"])
def game_state():
    """Estado del juego activo (modo 3 o 4)."""
    log_query("GET", "/api/v1/game/state")
    if GAME is None:
        return jsonify({"active": False, "mode": None})
    discovered = list(DISCOVERED)
    total = len(GAME["item_ids"])
    found = sum(1 for x in GAME["item_ids"] if x in DISCOVERED)
    return jsonify({
        "active": True,
        "mode": GAME["mode"],
        "themes": GAME["themes"],
        "total": total,
        "discovered": discovered,
        "found": found,
        "remaining": total - found,
        "started_at": GAME["started_at"],
        "ends_at": GAME.get("ends_at"),
        "finished": found >= total,
    })


@app.route("/api/v1/game/abandon", methods=["POST"])
def game_abandon():
    """Abandonar el juego activo."""
    log_query("POST", "/api/v1/game/abandon")
    global GAME, DISCOVERED
    if GAME is None:
        return jsonify({"error": "No hay juego activo"}), 404
    found = sum(1 for x in GAME["item_ids"] if x in DISCOVERED)
    total = len(GAME["item_ids"])
    summary = {
        "mode": GAME["mode"],
        "found": found,
        "total": total,
        "themes": GAME["themes"],
        "discovered_ids": list(DISCOVERED),
    }
    GAME = None
    DISCOVERED = set()
    # vaciar la DB del juego
    if "themes" in DB["loaded"]:
        del DB["loaded"]["themes"]
    return jsonify({"msg": "Juego abandonado", "summary": summary})


# ---------------------------------------------------------------------
# FILTRO DE TRAMPA — endpoints bloqueados en modo 3 y 4
# ---------------------------------------------------------------------
# Un endpoint está "trampa" cuando revela el contenido completo o
# permite filtrar sin restricción. En modo 3 / 4 devolvemos 403 con
# un mensaje claro.
TRAMPA_ENDPOINTS = (
    "/api/v1/db",
    "/api/v1/shells",
    "/api/v1/random",
    "/api/v1/categories",
    "/api/v1/severities",
)

@app.before_request
def trap_guard():
    """Bloquea endpoints trampa en modo 3/4. También bloquea
    /api/v1/commands sin filtros (sin ?cat=, ?q=, ?severity=)."""
    # ¿hay juego activo (modo 3 o 4)?
    active_mode = None
    if GAME is not None:
        active_mode = GAME["mode"]
    else:
        for r in ROOMS.values():
            if r["phase"] == "playing":
                active_mode = 4
                break
    if active_mode is None:
        return None  # modo libre, no bloquear nada
    path = request.path
    method = request.method
    if method != "GET":
        return None
    # no bloquear endpoints internos del modo 4
    if path.startswith("/api/v1/rooms"):
        return None
    # endpoints trampa totales
    for trampa in TRAMPA_ENDPOINTS:
        if path == trampa:
            return jsonify({
                "error": "Endpoint bloqueado en este modo",
                "hint": "En modo " + str(active_mode) + " no podés usar " + trampa + ". Usá /api/v1/commands?cat=<tema> o /api/v1/commands/<id>.",
                "mode": active_mode,
            }), 403
    # /api/v1/datasets — bloqueado también (revelaría lo cargado)
    if path == "/api/v1/datasets":
        return jsonify({
            "error": "Endpoint bloqueado en este modo",
            "hint": "En modo " + str(active_mode) + " no podés listar datasets. Usá /api/v1/commands?cat=<tema> para explorar por categoría.",
            "mode": active_mode,
        }), 403
    # /api/v1/datasets/<name> preview — bloqueado
    if path.startswith("/api/v1/datasets/") and method == "GET":
        return jsonify({
            "error": "Endpoint bloqueado en este modo",
            "hint": "Preview de datasets deshabilitado. Usá /api/v1/commands?cat=<tema> o /api/v1/commands/<id>.",
            "mode": active_mode,
        }), 403
    # /api/v1/commands sin filtros — bloqueado (debe tener al menos ?cat= o ?q=)
    if path == "/api/v1/commands":
        qs = request.args
        if not (qs.get("cat") or qs.get("q") or qs.get("severity") or qs.get("dataset")):
            return jsonify({
                "error": "Endpoint bloqueado en este modo",
                "hint": "En modo " + str(active_mode) + " /api/v1/commands exige al menos un filtro: ?cat=<tema>, ?q=<palabra>, ?severity=<nivel>",
                "mode": active_mode,
            }), 403
    return None


@app.after_request
def track_discoveries(resp):
    """Si el juego está activo y la respuesta trae items, los trackea como descubiertos."""
    try:
        if GAME is None and not ROOMS:
            return resp
        if resp.status_code >= 400:
            return resp
        # solo trackear GETs que devuelven items
        path = request.path
        if request.method != "GET":
            return resp
        # no trackear /game/state y /rooms para no contaminar
        if path == "/api/v1/game/state" or path.startswith("/api/v1/rooms"):
            return resp
        # decodificar body
        data = resp.get_json(silent=True)
        if not isinstance(data, dict):
            return resp
        # detectar IDs en respuesta
        new_ids = set()
        for cmd in data.get("commands", []) or []:
            if isinstance(cmd, dict) and cmd.get("id"):
                new_ids.add(cmd["id"])
        if data.get("id"):
            new_ids.add(data["id"])
        for r in data.get("results", []) or []:
            if isinstance(r, dict) and r.get("id"):
                new_ids.add(r["id"])
        if not new_ids:
            return resp

        # MODO 4: trackear en el discovered del jugador según ?pid=
        mode4_pid = request.args.get("pid")
        if mode4_pid:
            room_code = PLAYER_ROOM.get(mode4_pid)
            if room_code:
                r = ROOMS.get(room_code)
                if r and r["phase"] == "playing" and mode4_pid in r["players"]:
                    p = r["players"][mode4_pid]
                    p["discovered"].update(new_ids)
                    if len(p["discovered"]) >= r["items_per_player"]:
                        _finish_room_4(r["code"], reason=f"{p['name']} descubrió todo")
                    return resp

        # MODO 3: trackear en DISCOVERED global
        if GAME is not None:
            DISCOVERED.update(new_ids)
            if GAME and len(DISCOVERED & GAME["item_ids"]) >= len(GAME["item_ids"]):
                DB["history"].append({
                    "action": "game_finished",
                    "ts": utc_now_iso(),
                    "mode": GAME["mode"],
                    "found": len(DISCOVERED & GAME["item_ids"]),
                    "total": len(GAME["item_ids"]),
                })
    except Exception:
        pass
    return resp


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

    # detectar si estamos exponiendo fuera de loopback
    is_loopback = (host in ("127.0.0.1", "localhost", "::1"))
    PUBLIC_MODE = not is_loopback
    if PUBLIC_MODE:
        print(f"""
⚠  MODO PÚBLICO ACTIVADO
   El server está escuchando en {host}:{port} (no loopback).
   Se aplicará whitelist de IPs privadas (RFC 1918 + loopback).
   Requests desde internet (IPs públicas) serán rechazadas con 403.
   Rate limit: max {ROOM_CREATE_MAX} salas por IP cada {ROOM_CREATE_WINDOW}s.
   Para jugar en LAN, los 2 deben estar en la misma red privada.
""")

    print(f"""
╔════════════════════════════════════════════════════════════╗
║           API LAB — Pentesting & Linux                     ║
║                                                            ║
║   Servidor:  http://{host}:{port}                           ║
║   Datos:     {len([v for v in DATASETS.values() if v])} datasets disponibles                ║
║   DB ahora:  {len(DB["loaded"])} cargados · {sum(count_commands(d) for d in DB["loaded"].values())} comandos                                ║
║   Modo:      {'loopback (1 sólo máquina)' if is_loopback else 'LAN (whitelist IPs privadas ON)'}              ║
║                                                            ║
║   Páginas:                                                  ║
║     /         → home con selector de 4 modos                ║
║     /modo1    → DB pre-cargada (necesita --autoload)       ║
║     /consola  → modo 2: manual                             ║
║     /cargar   → botones CARGAR / VACIAR                    ║
║     /modo3    → juego random (single-player)               ║
║     /modo4    → 1 vs 1 (multijugador LAN)                  ║
║     /manual   → manual paso a paso                         ║
║                                                            ║
║   Ctrl+C para detener.                                     ║
╚════════════════════════════════════════════════════════════╝
""")
    # Usar waitress (production WSGI server) en lugar de Flask dev server.
    # Waitress es lo que recomienda Flask/Python para exponer el server
    # a una red. Si no está instalado, fallback a werkzeug.serving
    # con threaded=True (que es production-safe para 2 jugadores LAN).
    try:
        from waitress import serve
        print(f"✓ Usando waitress (production WSGI server)")
        print(f"  Listening on http://{host}:{port}")
        serve(app, host=host, port=port, ident="api-lab", threads=4)
    except ImportError:
        # fallback: werkzeug.serving con threaded=True
        # NO es el dev server de Flask (que es single-threaded y tira tracebacks).
        # Es un servidor WSGI de werkzeug que maneja concurrencia y no expone tracebacks.
        from werkzeug.serving import make_server
        print("⚠ waitress no instalado, usando werkzeug.serving (threaded=True)")
        print("  pip install waitress para mejor performance")
        if PUBLIC_MODE:
            print()
            print("  ⚠ Estás exponiendo a LAN. Ya está activada la whitelist de IPs privadas.")
            print("  ⚠ Para producción REAL, usá waitress + reverse proxy con TLS.")
        server = make_server(host=host, port=port, app=app, threaded=True)
        print(f"  Listening on http://{host}:{port}")
        server.serve_forever()