# AGENTS.md — Extensión Anti-Phishing Chrome

## ¿Qué hace este proyecto?
Extensión de Chrome (Manifest V3) que detecta señales de phishing
en español analizando texto de páginas web y correos electrónicos
mediante expresiones regulares y un sistema de umbral configurable.

## Stack
- JavaScript (vanilla, sin frameworks)
- HTML / CSS para el popup
- Chrome Extension APIs (Manifest V3)

## Archivos clave
- `popup.js` — lógica principal de análisis y UI del popup
- `popup.html` — interfaz del popup de la extensión
- `manifest.json` — configuración y permisos de la extensión

## Cómo correr y probar
1. Abre Chrome → `chrome://extensions`
2. Activa "Modo desarrollador"
3. Clic en "Cargar descomprimida" → selecciona esta carpeta
4. Recarga la extensión tras cada cambio en JS

## Convenciones de código
- JavaScript moderno (ES6+)
- Nombres de funciones en camelCase descriptivo
- Comentarios en español
- Sin dependencias externas por ahora

## Prioridades al modificar código
1. No romper la detección de phishing existente
2. Mantener rendimiento (corre en cada página visitada)
3. Código limpio y extensible para agregar nuevas señales
4. Seguir buenas prácticas de Manifest V3

## Lo que NO hacer
- No usar `eval()` ni `innerHTML` sin sanitizar (riesgo de seguridad)
- No agregar permisos al manifest sin documentar por qué
- No usar Manifest V2 — este proyecto es V3