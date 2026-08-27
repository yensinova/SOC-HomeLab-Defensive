\# 📄 Informe Técnico — Auditoría de Seguridad y Detección de Amenazas en Entorno Controlado



| | |

|---|---|

| \*\*Autor\*\* | Yensi Jesús González Nova |

| \*\*Fecha\*\* | 27/08/2026 |

| \*\*Versión\*\* | 1.0 |

| \*\*Clasificación\*\* | Pública (portafolio) |

| \*\*Framework de referencia\*\* | MITRE ATT\&CK · Metodología PICERL |



\---



\## 1. Objetivo



Validar la capacidad de detección y respuesta de un SIEM (Splunk 10.4.1) frente a técnicas de ataque reales ejecutadas de forma controlada, documentando evidencias, reglas de detección y procedimiento de triaje Tier 1.



\## 2. Alcance



\- Domain Controller Windows Server 2022 (`192.168.218.133`)

\- Endpoint Windows (`192.168.218.134`) con Sysmon (SwiftOnSecurity) y PowerShell Script Block Logging

\- SIEM Splunk 10.4.1 sobre Ubuntu 22.04 con Universal Forwarders

\- Estación de ataque Kali Linux (Nmap, CrackMapExec)



\## 3. Metodología



1\. \*\*Preparación:\*\* despliegue de VMs en red aislada, hardening de auditoría vía GPO, instalación de Sysmon y forwarders.

2\. \*\*Identificación:\*\* ejecución de ataques controlados y verificación de eventos generados.

3\. \*\*Detección:\*\* creación de consultas SPL de correlación.

4\. \*\*Contención / Erradicación / Recuperación:\*\* procedimiento de triaje documentado por caso.

5\. \*\*Lecciones aprendidas:\*\* sección 7.



\## 4. Hallazgos



\### H-01 · Servicios expuestos (Reconocimiento) — Severidad MEDIA

\- \*\*Técnica MITRE:\*\* T1046 (Network Service Discovery)

\- \*\*Evidencia:\*\* `05\_kali\_nmap\_scan\_dc.png` / `06\_kali\_nmap\_scan\_endpoint.png`

\- \*\*Detalle:\*\* puertos 445/tcp (SMB) y 3389/tcp (RDP) abiertos en ambos sistemas; 88/tcp filtrado.

\- \*\*Riesgo:\*\* habilita ataques de fuerza bruta, Pass-the-Hash y movimiento lateral.

\- \*\*Recomendación:\*\* restringir RDP/SMB por firewall a redes de administración; desactivar lo que no se use.



\### H-02 · Fuerza bruta contra cuenta privilegiada — Severidad ALTA

\- \*\*Técnica MITRE:\*\* T1110 (Brute Force)

\- \*\*Evidencia:\*\* `07\_detection\_bruteforce\_4625.png`

\- \*\*Detalle:\*\* 5 eventos \*\*4625\*\* en 15 minutos contra la cuenta `Administrator` (Logon Type 3).

\- \*\*Detección:\*\* regla SPL de agregación `EventCode=4625 ... where Failed\_Attempts >= 3`.

\- \*\*Respuesta aplicada (triaje Tier 1):\*\* hipótesis de password spraying → verificación de 4624 posteriores (sin compromiso confirmado) → recomendación de bloqueo de IP y ajuste de GPO de Account Lockout.



\### H-03 · Ejecución de PowerShell ofuscado (fileless) — Severidad CRÍTICA

\- \*\*Técnica MITRE:\*\* T1059.001 (PowerShell) + T1027 (Obfuscated Files or Information)

\- \*\*Evidencia:\*\* `08\_detection\_powershell\_4104.png`

\- \*\*Detalle:\*\* 33 eventos en `DESKTOP-043G7GC`: combinación de \*\*4104\*\* (Script Block Logging) y \*\*Sysmon 1\*\* mostrando `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand <Base64>`.

\- \*\*Detección:\*\* correlación SPL 4104 + Sysmon 1 con patrones `EncodedCommand`, `DownloadString`, `Net.WebClient`.

\- \*\*Respuesta aplicada (triaje Tier 1):\*\* aislamiento de red del endpoint sin apagar (preservación de RAM), extracción de línea de comandos y hash para consulta en inteligencia de amenazas, escalado a IR.



\## 5. Resumen de hallazgos



| ID | Hallazgo | MITRE | Severidad | Detectado por |

|---|---|---|---|---|

| H-01 | SMB/RDP expuestos | T1046 | Media | Nmap (reconocimiento) |

| H-02 | Fuerza bruta AD | T1110 | Alta | Splunk · Event 4625 |

| H-03 | PowerShell ofuscado | T1059.001 / T1027 | Crítica | Splunk · Event 4104 + Sysmon 1 |



\## 6. Verificación de telemetría



\- Forwarders conectados al Indexer: `index=\_internal group=tcpin\_connections` → hosts `.133` y `.134` (evidencia `03`).

\- Volumen de ingesta en 15 min: \*\*163 eventos\*\* (154 Sysmon, 7 Security, 2 PowerShell) (evidencia `04`).



\## 7. Lecciones aprendidas



1\. Ninguna fuente de logs por sí sola detecta todos los TTPs: la correlación \*\*Security + Sysmon + PowerShell\*\* es imprescindible.

2\. El Script Block Logging (4104) convierte el "PowerShell invisible" en visible: el comando Base64 quedó registrado y decodificable.

3\. El hardening preventivo (GPO de auditoría, Account Lockout, mínimo privilegio) reduce tanto el riesgo como el tiempo de triaje.



\## 8. Recomendaciones de hardening



1\. GPO de \*\*Account Lockout\*\* (bloqueo tras 5 intentos) + monitoreo de eventos 4740.

2\. Aplicar \*\*PowerShell Constrained Language Mode\*\* y AppLocker/WDAC a usuarios estándar.

3\. Implantar \*\*LAPS\*\* para contraseñas locales únicas y deshabilitar NTLMv1.

4\. Restringir RDP/SMB por firewall; segmentar red de administración.

5\. Mantener Sysmon con configuración actualizada y alertas SPL programadas.



\---

\*Informe generado como parte del proyecto SOC Home Lab Defensivo.\*

