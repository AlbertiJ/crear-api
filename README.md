# API Lab — Pentesting & Linux

> Un entorno portátil para practicar **reconocimiento y consumo de APIs REST** usando datos reales de pentesting y administración Linux. Ahora con **4 modos de juego** (consulta libre, manual, single-player random, y 1 vs 1 multijugador).

![status](https://img.shields.io/badge/status-active-success)
![version](https://img.shields.io/badge/version-1.2.0-00ff9c)
![python](https://img.shields.io/badge/python-3.8%2B-blue)
![flask](https://img.shields.io/badge/flask-3.x-000000)
![license](https://img.shields.io/badge/license-MIT-green)
![modes](https://img.shields.io/badge/modes-4-ff3ec8)

> 🆕 **v1.2.0** — 4 modos de juego: `Modo 1` (DB pre-cargada con `--autoload`), `Modo 2` (carga manual), `Modo 3` (juego random por tema, single-player), `Modo 4` (1 vs 1 multijugador LAN con código de sala, timer 1h, cross-over de DBs). Datasets de 3 temas: 🎵 música, 🎬 películas, 🦸 personajes (15 items cada uno).

---

## 💡 La idea

La mayoría de los recursos de pentesting vienen en formato **estático**: PDFs, archivos Markdown, HTML monolíticos. Sirven para consultar, pero no para *practicar* la habilidad que más se usa en una auditoría real: **descubrir y consultar APIs**.

**API Lab** te da un entorno con **4 modos** para que elijas cómo practicar:

1. **Modo 1** — DB pre-cargada, solo consultás (ideal para demos)
2. **Modo 2** — DB vacía, vos elegís qué cargar y borrar (manual)
3. **Modo 3** — Juego random: la PC arma la DB con un tema, vos descubrís qué hay
4. **Modo 4** — 1 vs 1: dos amigos, DBs se rotan, contrarreloj 1h

Es como un **CTF de pentesting web**, pero la "flag" es entender cómo se consume una API REST bien diseñada.

---

## 🎮 Los 4 modos

| Modo | URL | Quién carga | Qué hace | Para qué sirve |
|---|---|---|---|---|
| **1 — DB pre-cargada** | `/modo1` | El server al arrancar (`--autoload`) | DB ya viene con datos, vos solo consultás | Demos, enseñar, explorar sin setup |
| **2 — Manual** | `/cargar` | Vos elegís datasets (privesc, commands, clientes) | Botones CARGAR / VACIAR, vos armás la DB | Aprender el flujo discovery → load → query |
| **3 — Juego random** | `/modo3` | Vos elegís temas, la PC rellena random | DB secreta, vos descubrís con queries | Single-player: adivinar qué cargó la PC |
| **4 — 1 vs 1** | `/modo4` | Vos elegís tema, la PC rellena 15 items random, rival ve tu DB | Multijugador LAN, código de sala, timer 1h, cross-over | 1 vs 1: el que descubre más items gana |

### Modo 3 — flujo
1. Elegís 1 o más temas (🎵 música, 🎬 películas, 🦸 personajes)
2. Aprietan **▶ SEGUIR** → la PC arma la DB mezclando N items random
3. Endpoints trampa bloqueados: `/db`, `/datasets`, `/shells`, `/random`, `/commands` sin filtros
4. Solo podés consultar con `?cat=`, `?q=`, `?severity=` o por ID
5. Cada item nuevo que aparece en una respuesta → se marca en tu grilla
6. **🏳 ABANDONAR** o llenar la grilla → fin

### Modo 4 — flujo
1. **Host** crea sala con `python lab.py` y abre `http://IP:5050/modo4` → código de 4 chars
2. **Guest** se conecta a la misma IP y tipea el código
3. Cada uno tipea nombre, elige tema (mismo pool), PC rellena 15 items random
4. Aprietan **✓ LISTO** cuando los dos están listos
5. **Host** aprieta **▶ COMENZAR** → las DBs se rotan (cross-over) + timer 1h
6. Cada jugador consulta la DB del rival. Cada item nuevo → tachado en su grilla
7. Llenar la grilla o **🏳 ABANDONAR** o llegar a 1h → fin
8. **Ganador**: el que descubrió más. Empate si están iguales.

---

## 🎯 ¿Para quién es?

- Estudiantes de ciberseguridad que ya conocen comandos Linux pero nunca tocaron una API
- Practicantes de CTF que quieren un entorno controlado para experimentar
- Docentes que necesitan un lab autocontenido para enseñar `curl`, `fetch` y reconocimiento web
- Blue teamers que quieren entender qué logs genera un cliente API
- Parejas de amigos que quieran competir descubriendo qué cargó el otro

---

## ✨ Características

- 🎮 **4 modos de juego** (consulta libre, manual, random, multijugador)
- 🔌 **Dos modos de uso**: HTML standalone (sin instalar nada) o Python Flask (más realista)
- 💾 **DB en memoria** que arranca vacía — la llenás vos descubriendo los endpoints
- 🔍 **Filtros combinables**: por categoría, severidad, texto libre, dataset
- 🐚 **Datasets reales**: 100+ técnicas de privesc, 80+ comandos Linux, reverse shells
- 📦 **100% portable**: corre desde un pendrive USB sin instalación
- 🌑 **Cyberpunk UI** (Opción 1): dark mode, consola integrada, estadísticas en vivo
- 🛰️ **Endpoints de descubrimiento**: `/discovery`, `/fingerprint`, `/routes`, `/search`, `/random` y más
- 📖 **Manual HTML independiente** en `docs/MANUAL.html` — explicado paso a paso, en español
- 🏆 **Multijugador 1 vs 1** con código de sala, cross-over de DBs, timer 1h
- 🎲 **Modo 3 (juego random)** con grilla de descubiertos, abandono, fin automático

---

## 📂 Estructura del proyecto

```
crear-api/
├── data/                          # Datasets en JSON
│   ├── privesc.json               # 12 categorías de escalada de privilegios
│   ├── commands.json              # 9 categorías de comandos Linux
│   ├── clientes.json              # 5 clientes de prueba (DNI, CUIT, etc.)
│   └── themes/                    # Datasets para modos 3 y 4 (15 items c/u)
│       ├── musica.json            # Canciones, artistas, álbumes
│       ├── peliculas.json         # Películas icónicas
│       └── personajes.json        # Personajes de literatura, cine y TV
│
├── option1/                       # OPCIÓN 1: HTML standalone (zero-install)
│   └── api-lab.html               # Mock server en JS + UI cyberpunk
│
├── option2/                       # OPCIÓN 2: Python Flask server
│   ├── lab.py                     # API server con Flask (~1800 líneas)
│   ├── home.html                  # Home con selector de modo
│   ├── static_index.html          # Consola del modo 2
│   ├── cargar.html                # Botones CARGAR / VACIAR (modo 2)
│   ├── modo1.html                 # Modo 1 — DB pre-cargada
│   ├── modo3.html                 # Modo 3 — Juego random
│   ├── modo4.html                 # Modo 4 — 1 vs 1 multijugador
│   └── manual.html                # Manual HTML
│
├── docs/                          # Documentación extendida
│   ├── MANUAL.html                # Manual para principiantes (HTML)
│   └── README.md                  # Roadmap de docs
│
├── .gitignore                     # Exclusiones para Git
├── LICENSE                        # MIT
└── README.md                      # Este archivo
```

---

## 🚀 Inicio rápido

### Opción 1 — HTML Standalone (cero instalación)

```bash
# 1. Cloná el repo o descargá el ZIP
# 2. Abrí option1/api-lab.html con doble click
# 3. Listo. Empezá tipeando `help` en la consola
```

> **Ideal para**: llevar en un pendrive, usar en PCs donde no podés instalar nada, demos rápidas.

### Opción 2 — Python Flask (más realista, con los 4 modos)

```bash
# 1. Clonar
git clone https://github.com/AlbertiJ/crear-api.git
cd crear-api/option2

# 2. Instalar dependencias
pip install flask waitress              # waitress es opcional pero recomendada

# 3. Levantar servidor
python lab.py                          # puerto default 5050, solo localhost (seguro)
# o
python lab.py --port 5050              # cambiar puerto
python lab.py --host 0.0.0.0           # exponer en LAN — activa whitelist de IPs privadas
python lab.py --autoload privesc,commands   # arrancar con datasets (modo 1)

# 4. Abrir navegador
# → http://localhost:5050   (selector de modo con los 4 botones)
```

> **Ideal para**: practicar el flujo real de cliente/servidor, experimentar con `curl`, integrar con Postman, jugar 1 vs 1.

> ⚠️ **Modo LAN (`--host 0.0.0.0`)**: activa automáticamente una whitelist de IPs privadas (RFC 1918: 10.x, 172.16-31.x, 192.168.x + loopback). Cualquier request desde una IP pública es rechazada con 403. El server usa `waitress` (production WSGI) si está instalado, o `werkzeug.serving` con `threaded=True` como fallback. Si no instalás waitress, el server funciona igual pero es menos robusto.

**Para jugar 1 vs 1 en LAN**:
1. El host corre `python lab.py --host 0.0.0.0 --port 5050`
2. El host abre `http://localhost:5050/modo4` y crea la sala → obtiene un código de 4 chars
3. El host le pasa al guest: **(a)** su IP LAN (ej. `192.168.1.50`), **(b)** el código
4. El guest abre `http://192.168.1.50:5050/modo4`, tipea el código, se une
5. Los 2 eligen tema, listo, COMENZAR (solo host) → empieza la partida

---

## 📡 Endpoints completos

> Para descripciones largas, parámetros y ejemplos de cada endpoint, andá a:
> - 🖥️ **HTML**: <http://localhost:5050/api/v1/help>
> - 📄 **Texto plano**: `curl http://localhost:5050/api/v1/help.txt`
> - 📖 **Manual completo**: <http://localhost:5050/manual>

### Endpoints básicos
| Método | Path | Descripción |
|---|---|---|
| `GET`    | `/api/v1/discovery` | Info disclosure inicial del lab |
| `GET`    | `/api/v1/fingerprint` | Fingerprint del server |
| `GET`    | `/api/v1/routes` | Mapa completo de rutas |
| `GET`    | `/api/v1/health` | Health check + `server_ip` |
| `GET`    | `/api/v1/help` | Catálogo completo (JSON) |
| `GET`    | `/api/v1/help.txt` | Catálogo completo (texto plano) |
| `GET`    | `/manual` | Manual HTML para principiantes |

### Datasets
| Método | Path | Descripción |
|---|---|---|
| `GET`    | `/api/v1/datasets` | Datasets disponibles vs cargados |
| `GET`    | `/api/v1/datasets/<name>` | Preview de un dataset |
| `POST`   | `/api/v1/datasets/<name>/load` | Carga dataset a la DB |
| `DELETE` | `/api/v1/datasets/<name>` | Descarga dataset de la DB |

### Comandos y shells
| Método | Path | Descripción |
|---|---|---|
| `GET`    | `/api/v1/commands` | Busca comandos (`?cat`, `?q`, `?severity`, `?dataset`, `?limit`) |
| `GET`    | `/api/v1/commands/<id>` | Detalle de un comando |
| `GET`    | `/api/v1/shells` | Lista reverse shells |
| `GET`    | `/api/v1/shells/<id>` | Detalle de un shell |

### Estado y queries
| Método | Path | Descripción |
|---|---|---|
| `GET`    | `/api/v1/db` | Estado completo de la DB |
| `DELETE` | `/api/v1/db` | Vacía la DB |
| `GET`    | `/api/v1/queries` | Log de queries recientes |
| `GET`    | `/api/v1/stats` | Estadísticas agregadas |
| `GET`    | `/api/v1/severities` | Severidades con conteo |
| `GET`    | `/api/v1/categories` | Categorías cross-dataset |
| `GET`    | `/api/v1/schemas/<name>` | Schema de un dataset |
| `GET`    | `/api/v1/search` | Búsqueda full-text (`?q=`) |
| `GET`    | `/api/v1/random` | Comando aleatorio |

### Clientes (DB de prueba)
| Método | Path | Descripción |
|---|---|---|
| `GET`    | `/api/v1/clientes` | Lista clientes (`?limit`, `?offset`, `?apto`) |
| `GET`    | `/api/v1/clientes/<id>` | Detalle de un cliente |
| `GET`    | `/api/v1/clientes/search?q=` | Búsqueda por texto |

### Temas (modo 3 y 4)
| Método | Path | Descripción |
|---|---|---|
| `GET`    | `/api/v1/themes` | Lista temas disponibles con pool size |
| `POST`   | `/api/v1/themes/<tema>/random` | Single-tema: arma DB con N items random |
| `POST`   | `/api/v1/themes/random` | Multi-tema: body `{themes:[...], total:N}` |

### Juego (modo 3)
| Método | Path | Descripción |
|---|---|---|
| `GET`    | `/api/v1/game/state` | Estado del juego activo (modo 3) |
| `POST`   | `/api/v1/game/abandon` | Abandonar juego (modo 3) |

### Multijugador (modo 4)
| Método | Path | Descripción |
|---|---|---|
| `POST`   | `/api/v1/rooms` | Crea sala, devuelve `{code, player_id}` |
| `POST`   | `/api/v1/rooms/<code>/join` | Une a la sala |
| `GET`    | `/api/v1/rooms/<code>` | Estado público de la sala (`?pid=`) |
| `POST`   | `/api/v1/rooms/<code>/choose` | Elige tema, PC rellena 15 items |
| `POST`   | `/api/v1/rooms/<code>/ready` | Marca como listo |
| `POST`   | `/api/v1/rooms/<code>/start` | Inicia partida (solo host) — cross-over + timer |
| `POST`   | `/api/v1/rooms/<code>/abandon` | Abandonar partida |

### Páginas (HTML)
| Path | Descripción |
|---|---|
| `/` | Home con selector de 4 modos |
| `/modo1` | Modo 1 — DB pre-cargada |
| `/consola` | Consola del modo 2 |
| `/cargar` | Botones CARGAR / VACIAR |
| `/modo3` | Juego random (single-player) |
| `/modo4` | 1 vs 1 multijugador |
| `/standalone` o `/option1` | HTML standalone servido por Flask |
| `/manual` | Manual HTML paso a paso |

---

## 🧠 Metodología de aprendizaje sugerida

### Para practicar solo:
1. **Nivel 1 — Discovery**: Usá solo la Opción 1 (HTML) y los quick-actions. Familiarízate con el flujo.
2. **Nivel 2 — Cliente real**: Cambiate a la Opción 2 y usá `curl` en lugar del frontend.
3. **Nivel 3 — Modo 3**: Probá el juego random. ¿Podés descubrir los 15 items antes de abandonar?
4. **Nivel 4 — Defensa**: Analizá los logs de queries (`/api/v1/queries`) y pensá qué detecciones armarías en un SOC.
5. **Nivel 5 — Modificación**: Agregá tu propio dataset en formato JSON y recargá el server.

### Para competir con un amigo:
1. **Modo 4 setup**: Uno levanta el server con `python lab.py --host 0.0.0.0`
2. Los dos se conectan a `http://IP-DEL-SERVER:5050/modo4` (ambos en la misma LAN)
3. Uno crea sala, el otro se une con el código de 4 chars
4. Cada uno elige tema, listo, start
5. Tienen 1 hora para descubrir los 15 items del rival. Gana el que más descubra.

---

## 🛠️ Desarrollo

### 🔒 Seguridad (modo LAN)

Cuando se expone con `--host 0.0.0.0`, el server activa automáticamente:

| Capa | Detalle |
|---|---|
| **Whitelist de IPs** | Solo acepta requests de IPs privadas (loopback + RFC 1918). IP pública → 403. |
| **Rate limit** | Max 5 salas por IP cada 60 segundos (429 si excede). |
| **Server production** | Usa `waitress` (si está instalado) o `werkzeug.serving` con `threaded=True`. NO usa el dev server de Flask (que tira tracebacks). |
| **Log de accesos** | Cada request bloqueado por IP pública se loggea en `DB["history"]` con `action: blocked_public_ip`. |

> **Limitaciones**: este lab es para LAN entre amigos. NO está diseñado para exposición directa a internet. Si querés que sea público, ponelo detrás de un reverse proxy (nginx, Caddy) con TLS + autenticación (Authelia, oauth2-proxy, etc.).

### Agregar un dataset nuevo (modo 2)

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
    "mi_dataset": load_dataset_file("mi_dataset.json"),
}
```

### Agregar un tema nuevo (modo 3 y 4)

1. Creá `data/themes/<tema>.json`:
```json
{
  "name": "Bandas",
  "icon": "🎸",
  "description": "Bandas de rock internacionales",
  "items": [
    {"id": "ban_001", "nombre": "Led Zeppelin", "origen": "UK", "año_formacion": 1968, "genero": "Rock"},
    ... (mínimo 15 items)
  ]
}
```

2. Listo. El tema aparece automáticamente en `/api/v1/themes` y en los selectores del modo 3 y 4.

---

## 📋 Roadmap de cumplimiento (v1.2.0)

### ✅ Modo 1 — DB pre-cargada
- [x] Flag `--autoload ds1,ds2,...` al arrancar el server
- [x] Datasets se cargan ANTES de `app.run()`
- [x] Ruta `/modo1` con banner de stats en vivo
- [x] Botones CARGAR / VACIAR disponibles en modo 1 también
- [x] Mensaje claro si el server arrancó sin `--autoload`

### ✅ Modo 2 — Manual
- [x] DB arranca vacía
- [x] Página `/cargar` con cards de cada dataset
- [x] Botones **CARGAR** (verde) por dataset
- [x] Botones **VACIAR** (rojo) por dataset
- [x] Botón **🗑 VACIAR TODO** global con confirm
- [x] Topbar con "X cargados · Y comandos" en vivo
- [x] Auto-refresh cada 5 segundos
- [x] Funciona con privesc, commands, clientes

### ✅ Modo 3 — Juego random (single-player)
- [x] Pantalla de setup con 3 checks de temas (música, pelis, personajes)
- [x] Input "total de items en juego" (default 12)
- [x] Botón **▶ SEGUIR** deshabilitado hasta elegir al menos 1 tema
- [x] Backend: `POST /api/v1/themes/random` con body `{themes, total}`
- [x] Endpoints trampa bloqueados: `/db`, `/datasets`, `/shells`, `/random`, `/categories`, `/severities`, `/commands` sin filtros
- [x] Tracking automático de IDs descubiertos en cada response
- [x] Grilla de descubiertos al lado de la consola
- [x] Stats "X / Y descubiertos" + barra de progreso
- [x] Botón **🏳 ABANDONAR** con confirm
- [x] Pantalla de fin con trofeo "Los descubriste todos!" o "Te rendiste"
- [x] Botones "Otra partida" y "Volver al menú"

### ✅ Modo 4 — 1 vs 1 multijugador
- [x] Pantalla de landing con 2 cards: "Crear sala" / "Unirse con código"
- [x] Banner con IP del server (visible para que ambos se conecten)
- [x] Crear sala genera código de 4 chars alfanuméricos
- [x] Unirse con código de 4 chars
- [x] Pantalla de sala mostrando código grande y slots de jugadores
- [x] Pantalla de tema con 3 cards (música, pelis, personajes)
- [x] Cada jugador elige tema, PC rellena 15 items random
- [x] Pantalla de espera con checklist de 4 pasos
- [x] Botón **▶ COMENZAR PARTIDA** solo para el host cuando ambos están ready
- [x] **Cross-over de DBs** al iniciar: cada jugador ve la DB del rival
- [x] Timer regresivo de 1 hora
- [x] Auto-finalización cuando vence el timer
- [x] Grilla de descubiertos por jugador
- [x] Tracking separado por `?pid=` (cada jugador descubre los suyos)
- [x] Botón **🏳 ABANDONAR** por jugador
- [x] Pantalla de fin con VS (Vos VS Rival) + corona al ganador
- [x] Empate si ambos descubrieron la misma cantidad
- [x] Endpoints trampa bloqueados durante la partida

### Pendiente / ideas para v1.3
- [ ] Multijugador por internet (no solo LAN) — requiere deploy público
- [ ] Más temas: series, bandas, países, anime, deportes
- [ ] Chat en vivo entre jugadores en modo 4
- [ ] Replay: guardar historial de partidas
- [ ] Modo "torneo" (varios jugadores, eliminación)
- [ ] Tests automatizados para todos los endpoints
- [ ] CI/CD en GitHub Actions
- [ ] Versionado semántico automático

---

## 📖 Fuentes y referencias

Este lab se nutre de proyectos open source. Toda la información incluida está destinada a **uso educativo**.

### Cheatsheets base
- **[narufortix/CheatSheet](https://github.com/narufortix/CheatSheet)** — `linux-privesc-cheatsheet` y `pentesting-cheatsheet`
- **[GTFOBins](https://gtfobins.github.io/)** — Explotación de binarios Unix
- **[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)**
- **[HackTricks](https://book.hacktricks.xyz/)**
- **[PEASS-ng](https://github.com/carlospolop/PEASS-ng)** — LinPEAS

### CVEs incluidos
- **CVE-2022-0847** — DirtyPipe
- **CVE-2021-4034** — PwnKit
- **CVE-2021-3493** — Overlayfs
- **CVE-2016-5195** — DirtyC0w

---

## 📄 Licencia

MIT License — Ver [LICENSE](LICENSE).

---

## 👥 Créditos

- **Idea y desarrollo**: Juan Alberti
- **Programación e implementación**: MiniMax (Mavis)

---

## 🤝 Contribuciones

Ideas para contribuir:
- Sumar más datasets (Windows privesc, Active Directory, redes)
- Agregar más temas para modo 3 y 4 (series, bandas, países, anime, deportes)
- Traducir a otros idiomas
- Agregar un sistema de "misiones" / objetivos
- Mejorar la UI de la Opción 1
- Escribir tests para la API
- Implementar el modo torneo (varios jugadores)

PRs bienvenidos.

---

**Hecho con fines educativos. Aprendé, practicá, sé ético.** 🔐
