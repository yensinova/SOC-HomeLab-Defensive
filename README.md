# 🛡️ SOC Defensive Home Lab — Detección, Análisis y Respuesta a Amenazas

![SIEM](https://img.shields.io/badge/SIEM-Splunk%2010.4.1-blue)
![OS](https://img.shields.io/badge/OS-Windows%20Server%20%7C%20Ubuntu%2022.04-orange)
![Framework](https://img.shields.io/badge/MITRE-ATT%2CK-red)
![License](https://img.shields.io/badge/Status-Operational-green)

> **Autor:** Yensi Jesús González Nova | CompTIA Security+ (SY0-701)
> **Objetivo:** Emular las capacidades operativas de un SOC moderno (ingesta, detección, análisis y respuesta) en un entorno 100% gratuito y aislado, mapeando cada ataque al framework MITRE ATT&CK.
> **Fecha del proyecto:** Agosto 2026

---

## 📑 Índice
1. [Resumen Ejecutivo](#resumen-ejecutivo)
2. [Arquitectura del Laboratorio](#arquitectura-del-laboratorio)
3. [Cobertura de Detección y Triage](#cobertura-de-detección-y-triage)
4. [Ingeniería de Logs Implementada](#ingeniería-de-logs-implementada)
5. [Evidencias](#evidencias)
6. [Lecciones Aprendidas](#lecciones-aprendidas)
7. [Roadmap](#roadmap)

---

## 🎯 Resumen Ejecutivo

Este laboratorio fue diseñado para desarrollar y demostrar habilidades operativas de **Blue Team / SOC Analyst Tier 1-2**. El diseño aprovecha mi experiencia profesional en **GXO Logistics** administrando **Active Directory, GPOs y RBAC**, así como mis conocimientos en **VMware** aplicados en proyectos V&V para **Alstom**.

La arquitectura permite:

- **Detección proactiva** de técnicas de intrusión comunes (MITRE ATT&CK).
- **Correlación avanzada** de eventos entre logs de seguridad de Windows, Sysmon y PowerShell.
- **Respuesta a incidentes** aplicando la metodología PICERL (Preparación, Identificación, Contención, Erradicación, Recuperación, Lecciones aprendidas).
- **Hardening** mediante Políticas de Grupo (GPO) y auditoría avanzada.

---

## 🏗️ Arquitectura del Laboratorio

### Topología de Red
- **Hipervisor:** VMware Workstation (red aislada NAT/Host-Only `192.168.218.0/24`)
- **Segmentación:** Todas las máquinas en una red interna aislada para contención total de amenazas.

### Inventario de Componentes

| Rol | Sistema Operativo | Recursos | Función | IP |
|-----|-------------------|----------|---------|-----|
| **Domain Controller** | Windows Server 2022 Eval | 2 vCPU / 4 GB RAM | AD DS, DNS, GPOs de auditoría | `192.168.218.133` |
| **Endpoint Víctima** | Windows 10/11 Enterprise Eval | 2 vCPU / 4 GB RAM | Sysmon + PowerShell Logging | `192.168.218.134` |
| **SIEM** | Ubuntu Server 22.04 LTS | 2 vCPU / 4 GB RAM | Splunk Free 10.4.1 | `192.168.218.135` |
| **Atacante** | Kali Linux | 2 vCPU / 2 GB RAM | Atomic Red Team, Nmap, CrackMapExec | `192.168.218.136` |

### Flujo de Datos (Data Flow)
