# API Lab — Pentesting & Linux

> Un entorno portátil para practicar **reconocimiento y consumo de APIs REST** usando datos reales de pentesting y administración Linux.

![status](https://img.shields.io/badge/status-active-success)
![version](https://img.shields.io/badge/version-1.1.0-00ff9c)
![python](https://img.shields.io/badge/python-3.8%2B-blue)
![flask](https://img.shields.io/badge/flask-3.x-000000)
![license](https://img.shields.io/badge/license-MIT-green)
![offline](https://img.shields.io/badge/100%25-offline-orange)
![manual](https://img.shields.io/badge/manual-HTML-ff3ec8)

> 🆕 **v1.1.0** — 9 endpoints nuevos de descubrimiento (`/discovery`, `/fingerprint`, `/routes`, `/health`, `/severities`, `/categories`, `/schemas/<name>`, `/search`, `/random`). Puerto default **5050**. Manual HTML independiente en `docs/MANUAL.html`. [`/api/v1/help.txt`](#-ayuda-y-documentación) devuelve todo el catálogo en texto plano.

---

## 💡 La idea

La mayoría de los recursos de pentesting (cheatsheets, repos, blogs) vienen en formato **estático**: PDFs, archivos Markdown, HTML monolíticos. Sirven para consultar, pero no para *practicar* la habilidad que más se usa en una auditoría real: **descubrir y consultar APIs**.

**API Lab** invierte esa lógica. En lugar de darte una lista plana de comandos, te da un entorno donde:

1. La base de datos arranca **vacía**.
2. Los datasets existen como **endpoints HTTP que tenés que descubrir**.
3. Cargás los datos con `POST`, los filtrás con `GET`, los combinás con query params.
4. Practicás el flujo real de reconocimiento de APIs: **descubrir → cargar → consultar → filtrar**.

Es como un **CTF de pentesting web**, pero la "flag" es entender cómo se consume una API REST bien diseñada.

---

## 🎯 ¿Para quién es?

- Estudiantes de ciberseguridad que ya conocen comandos Linux pero nunca tocaron una API
- Practicantes de CTF que quieren un entorno controlado para experimentar
- Docentes que necesitan un lab autocontenido para enseñar `curl`, `fetch` y reconocimiento web
- Blue teamers que quieren entender qué logs genera un cliente API

---

## ✨ Características

- 🔌 **Dos modos de uso**: HTML standalone (sin instalar nada) o Python Flask (más realista)
- 💾 **DB en memoria** que arranca vacía — la llenás vos descubriendo los endpoints
- 🔍 **Filtros combinables**: por categoría, severidad, texto libre, dataset
- 🐚 **Datasets reales**: 100+ técnicas de privesc, 80+ comandos Linux, reverse shells
- 📦 **100% portable**: corre desde un pendrive USB sin instalación
- 🌑 **Cyberpunk UI** (Opción 1): dark mode, consola integrada, estadísticas en vivo
- 📊 **Stats en tiempo real** (Opción 2): logs de queries, estado de la DB, filtros
- 🔌 **API REST real** (Opción 2): usás `curl`, Postman, fetch del navegador — lo que sea
- 🛰️ **Endpoints de descubrimiento** (Opción 2): `/discovery`, `/fingerprint`, `/routes`, `/search`, `/random` y más
- 📖 **Manual HTML independiente** en `docs/MANUAL.html` — explicado paso a paso, en español
- 📄 **Help en texto plano** en `/api/v1/help.txt` — ideal para leer en la terminal

---

## 📂 Estructura del proyecto

```
crear-api/
├── data/                      # Datasets en JSON (puros datos, editables)
│   ├── privesc.json           # 12 categorías de escalada de privilegios
│   └── commands.json          # 9 categorías de comandos Linux
│
├── option1/                   # OPCIÓN 1: HTML standalone (zero-install)
│   └── api-lab.html           # Mock server en JS + UI cyberpunk
│
├── option2/                   # OPCIÓN 2: Python Flask server
│   ├── lab.py                 # API server con Flask
│   └── static_index.html      # Frontend del lab
│
├── docs/                      # Documentación extendida
│   ├── MANUAL.html            # 🆕 Manual para principiantes (HTML)
│   └── README.md              # Roadmap de docs
│
├── .gitignore                 # Exclusiones para Git
├── LICENSE                    # MIT
└── README.md                  # Este archivo
```

---

## 🚀 Inicio rápido

### Opción 1 — HTML Standalone (cero instalación)

1. Cloná el repo o descargá el ZIP
2. Abrí `option1/api-lab.html` con doble click
3. Listo. Empezá tipeando `help` en la consola

> **Ideal para**: llevar en un pendrive, usar en PCs donde no podés instalar nada, demos rápidas.

### Opción 2 — Python Flask (más realista)

```bash
# 1. Clonar
git clone https://github.com/AlbertiJ/crear-api.git
cd crear-api/option2

# 2. Instalar dependencia
pip install flask

# 3. Levantar servidor
python lab.py
# (o python lab.py --port 5050 para otro puerto)

# 4. Abrir navegador
# → http://localhost:5050
```

> **Ideal para**: practicar el flujo real de cliente/servidor, experimentar con `curl`, integrar con Postman.
>
> 📖 Si nunca tocaste una API, abrí [`docs/MANUAL.html`](docs/MANUAL.html) primero: te lleva de la mano paso a paso, en español, con diagramas.

### 🆕 v1.1.0 — endpoints de descubrimiento

Pensado para practicar **reconocimiento de APIs** (estilo pentest): lo primero que hacés es mapear la superficie del server. Esta versión suma:

- `GET /api/v1/discovery` — info disclosure inicial
- `GET /api/v1/fingerprint` — fingerprint del stack
- `GET /api/v1/routes` — mapa completo de rutas
- `GET /api/v1/health` — health check
- `GET /api/v1/severities` — severidades con conteo
- `GET /api/v1/categories` — categorías cross-dataset
- `GET /api/v1/schemas/<name>` — schema/forma de un dataset
- `GET /api/v1/search?q=...` — búsqueda full-text
- `GET /api/v1/random` — comando aleatorio

Empezá siempre por `/api/v1/discovery` y después `/api/v1/routes` para ver la superficie completa.

---

## 🎮 Cómo se usa

El lab arranca con la DB vacía. El flujo natural es:

```bash
# 1. RELEVAMIENTO — ver qué datasets hay disponibles
GET /api/v1/datasets

# 2. INSPECCIÓN — preview de un dataset sin cargarlo
GET /api/v1/datasets/privesc

# 3. CARGA — persistir el dataset en la DB
POST /api/v1/datasets/privesc/load

# 4. CONSULTA — buscar comandos con filtros
GET /api/v1/commands?severity=critical
GET /api/v1/commands?cat=suid
GET /api/v1/commands?q=python&severity=high
GET /api/v1/commands?cat=cron&q=path

# 5. EXPLORACIÓN — reverse shells
GET /api/v1/shells
GET /api/v1/shells/bash_tcp

# 6. ESTADO — ver qué hay cargado
GET /api/v1/db
GET /api/v1/stats

# 7. RESET — empezar de cero
DELETE /api/v1/db
```

### Ejemplo con `curl` (Opción 2)

```bash
# Cargar dataset
curl -X POST http://localhost:5000/api/v1/datasets/privesc/load

# Buscar comandos críticos
curl "http://localhost:5000/api/v1/commands?severity=critical" | jq

# Buscar reverse shells que usen python
curl "http://localhost:5000/api/v1/shells" | jq '.shells.python3'
```

---

## 📡 Endpoints completos

> Para descripciones largas, parámetros y ejemplos de cada endpoint, andá a:
> - 🖥️ **HTML**: <http://localhost:5050/api/v1/help>
> - 📄 **Texto plano**: `curl http://localhost:5050/api/v1/help.txt`
> - 📖 **Manual completo**: <http://localhost:5050/manual>

| Método | Path | Descripción |
|--------|------|-------------|
| `GET`    | `/api/v1/discovery` | Info disclosure inicial del lab |
| `GET`    | `/api/v1/fingerprint` | Fingerprint del server (framework, Python, encoding) |
| `GET`    | `/api/v1/routes` | Mapa completo de todas las rutas registradas |
| `GET`    | `/api/v1/health` | Health check básico |
| `GET`    | `/api/v1/severities` | Severidades con conteo de comandos |
| `GET`    | `/api/v1/categories` | Categorías cross-dataset con metadata |
| `GET`    | `/api/v1/schemas/<name>` | Schema/estructura de un dataset |
| `GET`    | `/api/v1/search` | Búsqueda full-text (?q=, ?limit=) sobre commands y shells |
| `GET`    | `/api/v1/random` | Comando aleatorio (?dataset=, ?severity=) |
| `GET`    | `/api/v1/datasets` | Datasets disponibles vs cargados |
| `GET`    | `/api/v1/datasets/<name>` | Preview o contenido de un dataset |
| `POST`   | `/api/v1/datasets/<name>/load` | Carga dataset a la DB |
| `DELETE` | `/api/v1/datasets/<name>` | Descarga dataset de la DB |
| `GET`    | `/api/v1/commands` | Busca comandos (?cat, ?q, ?severity, ?dataset, ?limit) |
| `GET`    | `/api/v1/commands/<id>` | Detalle de un comando específico |
| `GET`    | `/api/v1/shells` | Lista reverse shells |
| `GET`    | `/api/v1/shells/<id>` | Detalle de un shell |
| `GET`    | `/api/v1/db` | Estado completo de la DB |
| `DELETE` | `/api/v1/db` | Vacía la DB |
| `GET`    | `/api/v1/queries` | Log de queries recientes |
| `GET`    | `/api/v1/stats` | Estadísticas agregadas |
| `GET`    | `/manual` | Manual HTML para principiantes |
| `GET`    | `/api/v1/help.txt` | Catálogo completo en texto plano |

---

## 📚 Datasets incluidos

### 🔓 `privesc` — Linux Privilege Escalation

12 categorías basadas en la metodología de enumeración → vector → exploit → root:

| Categoría | Severidad | Descripción |
|-----------|-----------|-------------|
| `enumeration` | info | Comandos iniciales: `id`, `uname`, `ps`, `netstat` |
| `auto_enum` | info | Scripts automatizados: LinPEAS, LSE, LES |
| `suid` | critical | Binarios SUID/SGID explotables |
| `sudo` | critical | Configuraciones de `sudo` maliciosas |
| `cron` | high | Cron jobs con permisos inseguros |
| `capabilities` | high | Linux capabilities (cap_setuid, cap_dac_read_search) |
| `writable` | high | Archivos escribibles en `/etc`, `/var`, `/opt` |
| `path_hijacking` | high | Secuestro de PATH en scripts SUID |
| `kernel` | critical | CVEs de kernel: DirtyPipe, PwnKit, DirtyC0w |
| `credentials` | high | Caza de contraseñas, claves SSH, archivos `.env` |
| `ld_preload` | critical | Ataques con `LD_PRELOAD` + sudo |

**Bonus**: 7 reverse shells (bash TCP/UDP, Python, Netcat, Perl, PHP).

### 🐧 `commands` — Linux Commands Reference

9 categorías de comandos esenciales para uso diario:

| Categoría | Descripción |
|-----------|-------------|
| `system` | `uname`, `id`, `uptime`, `df`, `free`, `lscpu` |
| `files` | `ls`, `find`, `grep`, `chmod`, `tar` |
| `search` | `grep`, `sed`, `awk`, `cut`, `sort` |
| `processes` | `ps`, `top`, `kill`, `systemctl` |
| `networking` | `ip`, `ping`, `traceroute`, `curl`, `ssh`, `nc` |
| `users` | `who`, `useradd`, `passwd`, `sudo` |
| `ufw` | Firewall UFW |
| `cron` | Configuración de tareas programadas |
| `containers` | LXD container management |

---

## 🧠 Metodología de aprendizaje sugerida

1. **Nivel 1 — Discovery**: Usá solo la Opción 1 (HTML) y los quick-actions. Familiarízate con el flujo.
2. **Nivel 2 — Cliente real**: Cambiate a la Opción 2 y usá `curl` en lugar del frontend.
3. **Nivel 3 — Scripts**: Escribí un script en bash/Python que cargue todos los datasets y genere un reporte.
4. **Nivel 4 — Modificación**: Agregá tu propio dataset en formato JSON y recargá el servidor.
5. **Nivel 5 — Defensa**: Analizá los logs de queries (`/api/v1/queries`) y pensá qué detecciones armarías en un SOC.

---

## 🛠️ Desarrollo

### Agregar un dataset nuevo

1. Creá un JSON en `data/` siguiendo la estructura existente:

```json
{
  "name": "Mi Dataset",
  "description": "Descripción corta",
  "categories": {
    "cat1": {
      "title": "Categoría 1",
      "severity": "critical",
      "commands": [
        {"cmd": "comando ejemplo", "desc": "qué hace"}
      ]
    }
  }
}
```

2. (Opción 2) Registralo en `lab.py`:

```python
DATASETS = {
    "privesc":    load_dataset_file("privesc.json"),
    "commands":   load_dataset_file("commands.json"),
    "mi_dataset": load_dataset_file("mi_dataset.json"),  # ← agregar
}
```

3. (Opción 1) Agregalo al objeto `DATASETS` en el `<script>` del HTML.

### Stack técnico

- **Opción 1**: HTML + CSS + JS vanilla (sin frameworks, sin dependencias)
- **Opción 2**: Python 3.8+ + Flask 2.x
- **Datos**: JSON puro (editables a mano, no requiere schema)

---

## 📖 Fuentes y referencias

Este lab se nutre de proyectos open source de la comunidad. Toda la información incluida está destinada a **uso educativo** y a la administración **autorizada** de sistemas propios.

### Cheatsheets base

- **[narufortix/CheatSheet](https://github.com/narufortix/CheatSheet)** — `linux-privesc-cheatsheet` y `pentesting-cheatsheet`. Estructura, comandos y metodología.
  - [linux-privesc-cheatsheet online](https://narufortix.github.io/CheatSheet/linux-privesc-cheatsheet/)
  - [linux-cheatsheet repo](https://github.com/narufortix/linux-cheatsheet)
  - [pentesting-cheatsheet repo](https://github.com/narufortix/pentesting-cheatsheet)
  - Licencia: MIT

### Recursos mencionados en los datasets

- **[GTFOBins](https://gtfobins.github.io/)** — Explotación de binarios Unix
- **[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)** — Colección de payloads para pentesting
- **[HackTricks](https://book.hacktricks.xyz/)** — Guías de pentesting ofensivo
- **[Exploit-DB](https://www.exploit-db.com/)** — Base de datos de exploits
- **[PEASS-ng](https://github.com/carlospolop/PEASS-ng)** — Scripts de enumeración (LinPEAS)
- **[Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)** — Sugeridor de CVEs de kernel
- **[Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration)** — Alternativa a LinPEAS

### CVEs incluidos

- **CVE-2022-0847** — DirtyPipe (kernel 5.8-5.16)
- **CVE-2021-4034** — PwnKit (pkexec)
- **CVE-2021-3493** — Overlayfs (Ubuntu 20.04)
- **CVE-2016-5195** — DirtyC0w (kernel < 4.8.3)

### Material de aprendizaje complementario

- **Universidad de Helsinki — Python MOOC** (vía midudev, LinkedIn) — Para practicar scripting contra la API
- **Comandos esenciales de Linux** (vía midudev, LinkedIn) — Base para entender los comandos del dataset
- **Linux para Blue Team** (vía Vlad Nicusor Sarpe, LinkedIn) — Perspectiva defensiva de los mismos vectores
- **OSINT en GitHub** (vía Kenny Felix, LinkedIn) — Para expandir datasets desde fuentes públicas
- **Reverse shells Windows** (vía Valvis Defense, LinkedIn) — Perspectiva adicional sobre shells

---

## 📖 Ayuda y documentación

Cuando el server está corriendo hay tres formas de consultar la ayuda:

| Dónde | Qué es | Cuándo usarlo |
|---|---|---|
| <http://localhost:5050/manual> | Manual HTML para principiantes | Si nunca tocaste una API o querés el paso a paso visual |
| <http://localhost:5050/api/v1/help> | Help en JSON, agrupado por categoría | Si querés un objeto parseable, agrupado por `descubrimiento / datasets / commands / shells / estado` |
| `curl http://localhost:5050/api/v1/help.txt` | Help en texto plano formateado | Si estás en la terminal y querés leer el catálogo con `less` o `cat` |

El manual HTML (`docs/MANUAL.html`) es **un archivo independiente**: lo podés abrir directamente con doble click sin tener el server levantado. También lo sirve el server en `/manual` para tenerlo todo junto.

---

## ⚠️ Disclaimer

Este proyecto está diseñado **exclusivamente para**:

- Educación en ciberseguridad
- Práctica en entornos controlados (laboratorios propios, CTFs autorizados)
- Auditorías de seguridad con autorización explícita

El uso de estas técnicas contra sistemas sin permiso es **ilegal** y va contra la ética del campo. Sé responsable.

---

## 📄 Licencia

MIT License — Ver [LICENSE](LICENSE).

---

## 🤝 Contribuciones

Ideas para contribuir:

- Sumar más datasets (Windows privesc, Active Directory, redes, etc.)
- Traducir a otros idiomas
- Agregar un sistema de "misiones" / objetivos
- Mejorar la UI de la Opción 1
- Escribir tests para la API

PRs bienvenidos.

---

**Hecho con fines educativos. Aprendé, practicá, sé ético.** 🔐