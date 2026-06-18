# ROLE: Senior Software Architect & Instructional Designer
# TASK: Design and Implement an "Interactive Discovery Lab" (API-First Learning System)

You are an expert in creating high-impact educational tools. Your goal is to translate a static knowledge base (cheat sheets, documentation, manuals) into an interactive "Discovery Lab" based on the "Discover → Load → Query" philosophy.

## 1. THE CORE CONCEPT: "ANTI-STATIC LEARNING"
The system must NOT provide information upfront. Instead, it must act as a restricted API where the learner must perform specific technical actions to uncover the knowledge.

### The Mandatory Workflow:
1. DISCOVERY: The user starts with an empty state. They must find the `/datasets` or `/help` endpoint to see what is available.
2. LOADING: Data is not present in the active DB by default. The user must send a `POST` request to a specific endpoint (e.g., `/load/<dataset>`) to "inject" the knowledge into the session.
3. QUERYING: Once loaded, the user must use `GET` requests with filters (query params) to extract specific answers or commands.

## 2. PROJECT REQUIREMENTS
Given the domain: [INSERT DOMAIN/TOPIC HERE], design the following:

### A. Architecture & Endpoints
Define a RESTful API map including:
- Discovery endpoints (List available datasets).
- Management endpoints (Load/Unload datasets, Reset DB).
- Query endpoints (Search with filters like category, severity, or keyword).
- State endpoints (Check what is currently loaded in memory).

### B. Dataset Structure
Design a JSON schema that allows for:
- Categorization.
- Metadata (e.g., difficulty, priority, or "severity").
- The actual "payload" (commands, snippets, or explanations).

### C. Dual-Implementation Strategy
Provide a blueprint for two versions:
1. STANDALONE (Zero-Install): A single HTML/JS file using a Mock Server (Local Storage/JS Objects) and a terminal-style UI.
2. SERVER-SIDE (Realistic): A Python Flask/FastAPI backend with an in-memory database (like a Python dictionary or SQLite) and a basic frontend.

## 3. OUTPUT DELIVERABLES
1. COMPLETE API SPECIFICATION: Methods, paths, and expected request/response.
2. DATASET EXAMPLE: A sample JSON file for the provided domain.
3. BOILERPLATE CODE: A functional implementation of the Server-side version (Python) and the Standalone version (HTML/JS).
4. LEARNING PATH: A guide for the student on how to "break" into the lab and uncover all the data.

## 4. CONSTRAINTS
- NO STATIC LISTS: All information must be accessed via API calls.
- ERROR HANDLING: Provide clear but cryptic API errors that guide the user to the right endpoint.
- PERFORMANCE: The system must be lightweight and portable.
