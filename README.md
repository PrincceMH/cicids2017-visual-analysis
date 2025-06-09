#  cicids2017-visual-analysis

Análisis visual exploratorio del dataset CICIDS2017 enfocado en el comportamiento de direcciones IP maliciosas.

---

##  Avance de implementación – Semana actual

> **Fase exploratoria de prueba para entender el dataset.**

Este avance corresponde a la primera etapa de implementación del proyecto de tesis titulado:

**“Aplicación de Visual Analytics para el análisis temporal de una dirección IP maliciosa en entornos de ciberseguridad”**

En esta etapa se buscó comprender la estructura, etiquetas y patrones generales del dataset **CICIDS2017** mediante una visualización dinámica construida con **Dash** y **Plotly**.

---

##  Objetivo alcanzado en esta fase

> Según el documento de tesis (Objetivo Específico 1):

> *"Analizar y preparar el dataset CICIDS2017, aplicando técnicas de preprocesamiento y limpieza con el fin de garantizar la calidad y consistencia de los datos."*

Este avance cumple dicho objetivo al:

- Realizar carga eficiente de los archivos `.csv` limpios del dataset CICIDS2017.
- Normalizar campos como `Timestamp` y `ProtocolName`.
- Implementar un dashboard exploratorio con filtros y múltiples visualizaciones.
- Permitir el análisis por IP maliciosa, protocolo y duración del flujo.

Este análisis inicial facilita la **comprensión profunda del comportamiento de eventos maliciosos**, punto clave para las próximas etapas de modelado y métricas.

---
##  Funcionalidades implementadas

 Dashboard interactivo que permite:

- Filtrar por protocolo, duración de flujo y direcciones IP maliciosas.
- Visualizar la línea de tiempo de una IP seleccionada.
- Ver patrones de tráfico por hora, distribución de etiquetas, protocolos y duración.
- Explorar correlaciones numéricas en el dataset.

---

## 📷 Capturas del sistema en ejecución (`http://127.0.0.1:8050`)

> A continuación se muestran vistas reales del dashboard funcional con datos limpios.

<div align="center">


![image](https://github.com/user-attachments/assets/d0d1d848-39ad-4874-81e8-c81fdff3a6ce)

![image](https://github.com/user-attachments/assets/184e948d-918b-49c0-b264-7e7e6077dd68)


![image](https://github.com/user-attachments/assets/ad2e700b-f942-42d7-b390-8743f59ee877)

</div>

---

##  Estructura de archivos

- [`/app/app.py`](./app/app.py): Código principal del dashboard (Dash + Plotly).
- [`requirements.txt`](./requirements.txt): Librerías necesarias para ejecutar el entorno.

---

##  Observaciones

 Este avance es **una prueba piloto** que permitirá validar hipótesis futuras del proyecto. El conocimiento adquirido sobre la estructura del dataset facilitará:

- El modelado posterior con grafos dirigidos.
- La construcción de métricas personalizadas como **entropía**, **tasa de conexión** y **latencia entre eventos**.
- La mejora del sistema de visualización para el análisis cronológico por IP.

---

## Próximos pasos

- Implementar modelo de red de eventos tipo grafo.
- Incorporar métricas de comportamiento.
- Permitir visualización comparativa entre IPs benignas y maliciosas.
- Automatizar la selección de IPs sospechosas por frecuencia y tipo de ataque.

---

> Este repositorio constituye la evidencia solicitada por el docente para verificar el avance de esta semana.


