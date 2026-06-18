# =============================================================
# CLIENTES — DB de prueba
# =============================================================
# Este archivo es la versión "con código comentado" de data/clientes.json.
# Acá podés ver, agregar y modificar clientes con comentarios
# que explican qué hace cada bloque.
#
# Para regenerar el JSON a partir de este Python, ejecutá:
#     python data/clientes_db.py
# Eso pisa data/clientes.json con el contenido actual de CLIENTES + SCHEMA.
# =============================================================

import json
from pathlib import Path

# =============================================================
# SCHEMA — la "forma" que tiene cada cliente
# =============================================================
# ESTE BLOQUE HACE: declara qué campos existen y qué tipo de
#                   dato va en cada uno.
# MODIFICANDO ESTO: podés agregar o quitar campos. Si agregás
#                   un campo nuevo, también tenés que ponerlo en
#                   cada item de la lista CLIENTES de abajo.
# RESPETAR ESTO: el nombre de la clave (lo que va a la izquierda
#                de los ":") tiene que ser IDÉNTICO en el schema
#                y en cada item. Mayúsculas, acentos y espacios
#                cuentan.
# =============================================================
SCHEMA = {
    "id":                "int    (autoincremental)",
    "ID":                "string (identificador externo, ej. UUID o código de país)",
    "nombres":           "string (uno o más nombres)",
    "apellidos":         "string (uno o más apellidos)",
    "DOC. tipo":         "string (DNI, PAS, LE, LC)",
    "DNI":               "string (8 dígitos) o None si no tiene",
    "CUIT":              "string (formato XX-XXXXXXXX-X)",
    "Registro civil":    "string (código de registro civil) o None",
    "Domicilio":         "string (dirección principal)",
    "Domicilios":        "list   (array de strings con todas las direcciones)",
    "Test1":             "any    (campo de test, el tipo puede variar)",
    "Test2":             "any    (campo de test, el tipo puede variar)",
    "Registro conducir": "string (categoría + número) o None si no tiene registro",
    "tipo de sangre":    "string (A+, A-, B+, B-, AB+, AB-, O+, O-)",
    "creditos":          "number (puede ser negativo, según deuda o saldo)",
    "apto":              "bool   (True/False)",
    "no apto":           "bool   (True/False — generalmente opuesto a 'apto')",
}

# =============================================================
# CLIENTES — los datos en sí
# =============================================================
# ESTE BLOQUE HACE: guarda una lista de 5 clientes de ejemplo
#                   con datos variados a propósito.
# MODIFICANDO ESTO: podés agregar más clientes copiando un dict
#                   y cambiándole el id, o cambiar los valores
#                   de los que ya están.
# RESPETAR ESTO:
#   1. Cada cliente es un dict { "campo": valor, ... }
#   2. TODOS los campos del SCHEMA tienen que estar presentes en
#      cada cliente. Si no aplica, poné None.
#   3. El campo "id" no se puede repetir.
#   4. Los nombres de los campos tienen que ser EXACTAMENTE
#      iguales a los del SCHEMA (mayúsculas, acentos, espacios,
#      todo cuenta — ojo con "DOC. tipo", "no apto", etc.).
# =============================================================
CLIENTES = [
    {
        # --- cliente 1: caso "completo" ---
        "id": 1,
        "ID": "AR-2024-0001",
        "nombres": "María Fernanda",
        "apellidos": "González Pérez",
        "DOC. tipo": "DNI",
        "DNI": "28456789",
        "CUIT": "27-28456789-4",
        "Registro civil": "RC-001234",
        "Domicilio": "Av. Corrientes 1234, CABA",
        "Domicilios": ["Av. Corrientes 1234, CABA", "Calle 60 nro 456, La Plata"],
        "Test1": True,
        "Test2": None,
        "Registro conducir": "B1-123456",
        "tipo de sangre": "A+",
        "creditos": 1500,
        "apto": True,
        "no apto": False,
    },
    {
        # --- cliente 2: caso "no apto" + Test2 como string ---
        "id": 2,
        "ID": "AR-2024-0002",
        "nombres": "Juan Carlos",
        "apellidos": "Pérez Rodríguez",
        "DOC. tipo": "DNI",
        "DNI": "32145678",
        "CUIT": "20-32145678-9",
        "Registro civil": "RC-001235",
        "Domicilio": "Calle 50 nro 678, La Plata",
        "Domicilios": ["Calle 50 nro 678, La Plata"],
        "Test1": False,
        "Test2": "valor X",
        "Registro conducir": "B2-234567",
        "tipo de sangre": "O-",
        "creditos": 0,
        "apto": False,
        "no apto": True,
    },
    {
        # --- cliente 3: caso "DNI null" porque es PAS ---
        "id": 3,
        "ID": "AR-2024-0003",
        "nombres": "Ana Lucía",
        "apellidos": "Martínez López",
        "DOC. tipo": "PAS",
        "DNI": None,
        "CUIT": "23-35678901-4",
        "Registro civil": "RC-001236",
        "Domicilio": "Av. Rivadavia 5432, CABA",
        "Domicilios": ["Av. Rivadavia 5432, CABA", "Belgrano 234, Quilmes"],
        "Test1": None,
        "Test2": None,
        "Registro conducir": "A1-345678",
        "tipo de sangre": "B+",
        "creditos": 750,
        "apto": True,
        "no apto": False,
    },
    {
        # --- cliente 4: caso "sin registro conducir" + Test2 numérico ---
        "id": 4,
        "ID": "AR-2024-0004",
        "nombres": "Luis Alberto",
        "apellidos": "Fernández Suárez",
        "DOC. tipo": "DNI",
        "DNI": "40123456",
        "CUIT": "20-40123456-3",
        "Registro civil": "RC-001237",
        "Domicilio": "San Martín 890, Mar del Plata",
        "Domicilios": ["San Martín 890, Mar del Plata"],
        "Test1": True,
        "Test2": 42,
        "Registro conducir": None,
        "tipo de sangre": "AB+",
        "creditos": 3200,
        "apto": True,
        "no apto": False,
    },
    {
        # --- cliente 5: caso "varios domicilios" + créditos negativos ---
        "id": 5,
        "ID": "AR-2024-0005",
        "nombres": "Sofía Inés",
        "apellidos": "Sánchez Castro",
        "DOC. tipo": "DNI",
        "DNI": "45789123",
        "CUIT": "27-45789123-8",
        "Registro civil": "RC-001238",
        "Domicilio": "Mitre 234, Lanús",
        "Domicilios": ["Mitre 234, Lanús", "Av. San Martín 1100, Lanús", "Casa quinta en Mar del Plata"],
        "Test1": False,
        "Test2": "pendiente",
        "Registro conducir": "B1-456789",
        "tipo de sangre": "O+",
        "creditos": -150,
        "apto": False,
        "no apto": True,
    },
]

# =============================================================
# VALIDADOR — chequea que todo esté prolijo
# =============================================================
# ESTE BLOQUE HACE: verifica que cada cliente respete el schema
#                   y que no haya ids repetidos.
# MODIFICANDO ESTO: si agregás campos nuevos, actualizá la
#                   función _check() para que también los valide.
# RESPETAR ESTO: si este validador tira error, el JSON no se
#                regenera. No lo comentes salvo que sea para
#                testear.
# =============================================================
def _check():
    # 1. Verificar que cada campo del schema exista en TODOS los clientes
    campos_requeridos = set(SCHEMA.keys())
    for cli in CLIENTES:
        campos_cli = set(cli.keys())
        faltantes  = campos_requeridos - campos_cli
        sobrantes  = campos_cli - campos_requeridos
        if faltantes:
            raise ValueError(f"Cliente id={cli.get('id')}: faltan campos {faltantes}")
        if sobrantes:
            raise ValueError(f"Cliente id={cli.get('id')}: sobran campos {sobrantes} (no están en SCHEMA)")
    # 2. Verificar que no haya ids repetidos
    ids = [c["id"] for c in CLIENTES]
    if len(ids) != len(set(ids)):
        duplicados = [i for i in ids if ids.count(i) > 1]
        raise ValueError(f"Hay ids repetidos: {set(duplicados)}")

# =============================================================
# EXPORT A JSON — regenera data/clientes.json
# =============================================================
# ESTE BLOQUE HACE: arma el JSON final con name, description,
#                   schema, e items, y lo guarda en
#                   data/clientes.json (sobreescribiendo el
#                   archivo existente).
# MODIFICANDO ESTO: solo si querés cambiar la ruta de salida o
#                   la estructura del JSON resultante.
# RESPETAR ESTO: ejecutá este archivo con `python clientes_db.py`
#                para regenerar el JSON. No tocar el SCHEMA ni
#                CLIENTES desde el JSON directamente: editá este
#                .py y regenerá.
# =============================================================
def export_json():
    _check()  # validar antes de exportar
    payload = {
        "name": "Clientes (Test DB)",
        "description": "DB de prueba con campos de cliente y 5 items aleatorios. Para testear consumo de APIs y manejo de campos heterogéneos (algunos nulos, algunos arrays, booleanos opuestos).",
        "schema": SCHEMA,
        "items": CLIENTES,
    }
    out_path = Path(__file__).resolve().parent / "clientes.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"OK -> {out_path}  ({len(CLIENTES)} clientes)")

if __name__ == "__main__":
    export_json()
