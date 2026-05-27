# Diseño de Flujos Automáticos para la Respuesta al Incidente

**Proyecto:** Trabajo de Integración Curricular — Sistema de Detección y Respuesta ante Incidentes en AWS  
**Componente:** C — Automatización de Respuesta  
**Responsable:** Bryan  
**Fecha:** 2026-04-28

---

## ¿De qué trata este documento en una sola frase?

Responde a esta pregunta: **¿cómo le decimos al sistema qué hacer automáticamente cuando detecta un ataque?** Y compara 3 formas de hacerlo.

---

## La idea central

Cuando el sistema detecta un ataque, necesita reaccionar solo, sin que nadie haga nada manualmente. Para eso necesita un "flujo" — una secuencia de pasos automáticos. Este documento compara 3 diseños posibles para ese flujo.

---

## Diseño A — SNS Directo (el más simple, el que NO usamos)

Cada tipo de ataque tiene su propio "botón de alarma" y ese botón activa directamente una acción.

```
Ataque de fuerza bruta → botón 1 → Lambda "bloquear IP"
Credencial robada      → botón 2 → Lambda "revocar credenciales"
```

**¿Por qué no lo usamos?**
- Si se quieren hacer dos cosas ante un ataque (avisar Y bloquear), SNS no las encadena bien.
- Si la Lambda falla, el mensaje se pierde y nadie se entera.

---

## Diseño B — SQS + Dispatcher (el que SÍ implementamos)

Hay un "jefe coordinador" — la Lambda `dispatcher`. Funciona así:

1. El simulador detecta un ataque y pone un mensaje en una **cola** (SQS).
2. La cola le avisa automáticamente al dispatcher.
3. El dispatcher lee el tipo de ataque y decide qué hacer.
4. Llama a los playbooks necesarios en orden.

```
Ataque detectado
   → Cola SQS (guarda el mensaje)
      → Dispatcher (lee el mensaje, decide)
         → Primero avisa al equipo (notify-alert)
         → Luego bloquea la IP (block-ip)
```

**¿Por qué es mejor?**
- Si algo falla, la cola guarda el mensaje y lo reintenta hasta 3 veces.
- Todo queda registrado en un solo lugar (logs del dispatcher).
- Agregar un nuevo tipo de ataque = agregar una línea en la tabla del dispatcher, nada más.

**¿Qué es el "Event Source Mapping"?**
Es la conexión automática entre la cola SQS y el dispatcher. Le dice a AWS: *"cada vez que llegue un mensaje a esta cola, activa esta Lambda"*. No hay que hacer nada manualmente.

---

## Diseño C — Step Functions (el más potente, el que NO podemos usar)

Es como un diagrama de flujo visual con cajas y flechas, donde cada caja es un paso y si algo falla hay reintentos automáticos con espera entre intentos.

**¿Por qué no lo usamos?**
- No está disponible en la versión gratuita de LocalStack.
- Es demasiado complejo para lo que necesita la tesis.

---

## Decisiones de diseño

**¿Por qué usamos SQS y no SNS para recibir los ataques?**
Porque SNS puede perder mensajes si la Lambda falla. SQS los guarda y reintenta. En seguridad no se puede permitir perder un incidente.

**¿Por qué se procesa un mensaje a la vez?**
Porque si el dispatcher procesa dos ataques al mismo tiempo, podrían pisarse entre sí al escribir en el mismo archivo de S3. Uno a la vez es más seguro.

**¿Por qué `notify-alert` va siempre primero?**
Porque aunque el bloqueo falle, el equipo ya fue avisado. Lo peor que puede pasar es que el bloqueo no funcione, pero al menos alguien sabe que hubo un ataque.

---

## Resumen visual

```
Problema: ¿Cómo automatizar la respuesta a un ataque?

Opción A: SNS → Lambda directa        ← simple pero poco confiable
Opción B: SQS → Dispatcher → Lambdas  ← lo que usamos, balance ideal
Opción C: Step Functions              ← muy potente pero no disponible

Lo que implementamos (Opción B):
Simulador → Cola SQS → Dispatcher → notify-alert + block-ip / revoke / isolate
```
