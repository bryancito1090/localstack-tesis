# Perspectiva del Atacante — Materialización del Incidente

**Proyecto:** Trabajo de Integración Curricular — Sistema de Detección y Respuesta ante Incidentes en AWS  
**Componente:** C — Automatización de Respuesta  
**Responsable:** Bryan  
**Fecha:** 2026-04-28

> **Nota:** Este documento tiene propósito académico. Describe cómo un atacante intentaría comprometer un entorno AWS y cómo el sistema del Componente C lo detecta y responde automáticamente.

---

## La idea general

El atacante no ve una pantalla con alertas diciéndole "te estamos vigilando". Desde su punto de vista, está interactuando con servicios normales de AWS — la consola web, una API, un bucket S3. Lo que no sabe es que cada acción que hace queda registrada en CloudTrail, y que el sistema está leyendo esos registros en tiempo real.

```
Atacante actúa sobre AWS
       │
       ▼
AWS registra todo en CloudTrail (log de cada acción)
       │
       ▼
El sistema lee los logs y busca patrones sospechosos
       │
       ▼
Si detecta algo → responde automáticamente
```

---

## Ataque 1 — Fuerza Bruta (BRUTE_FORCE)

**¿Qué intenta el atacante?**
Entrar a la consola de AWS adivinando la contraseña de un usuario. Prueba combinaciones una por una: `admin123`, `Welcome1`, `P@ssw0rd`, etc.

**¿Qué ve el atacante?**
Cada intento le devuelve un error de "credenciales incorrectas". Sigue probando.

**¿Qué registra AWS?**
Cada intento fallido genera un evento `ConsoleLogin` con `errorCode: AccessDenied`. Tras 10 intentos desde la misma IP, el patrón es claro.

**¿Cómo responde el sistema?**
```
Detecta: +5 intentos fallidos desde la misma IP en menos de 5 minutos
   → notify-alert: avisa al equipo de seguridad
   → block-ip: registra la IP del atacante en la lista de bloqueados
```

**¿Qué siente el atacante?**
No sabe que fue detectado. Sus intentos siguen fallando, pero ahora también hay un equipo revisando su IP.

---

## Ataque 2 — Credencial Robada (CREDENTIAL_LEAK)

**¿Qué intenta el atacante?**
Encontró una `AWS_ACCESS_KEY_ID` y un `AWS_SECRET_ACCESS_KEY` expuestos en un repositorio público de GitHub. Con esas dos claves puede llamar a la API de AWS directamente, sin necesidad de contraseña.

**¿Qué ve el atacante?**
Tiene acceso real. Puede listar buckets S3, ver recursos, ejecutar comandos. Cree que nadie lo sabe.

**¿Qué registra AWS?**
Cada llamada a la API queda registrada con la key usada. El sistema detecta que esa key está siendo usada desde una IP desconocida o en horarios inusuales.

**¿Cómo responde el sistema?**
```
Detecta: uso de credencial comprometida
   → notify-alert: avisa al equipo
   → revoke-credentials: desactiva la access key inmediatamente
```

**¿Qué siente el atacante?**
A los pocos segundos, todos sus comandos empiezan a fallar con `InvalidClientTokenId`. La llave fue desactivada mientras la usaba.

---

## Ataque 3 — Escalada de Privilegios (PRIVILEGE_ESCALATION)

**¿Qué intenta el atacante?**
Ya tiene acceso a AWS con una cuenta de bajos privilegios (por ejemplo, un usuario que solo puede leer logs). Intenta darse a sí mismo permisos de administrador ejecutando comandos como `iam:AttachUserPolicy` o `iam:CreateRole`.

**¿Qué ve el atacante?**
Está ejecutando comandos IAM que normalmente no debería poder usar. Intenta escalar sus permisos para tener control total de la cuenta.

**¿Qué registra AWS?**
Los eventos IAM inusuales quedan en CloudTrail. Un usuario con perfil de "solo lectura" intentando modificar políticas es una señal clara.

**¿Cómo responde el sistema?**
```
Detecta: llamadas IAM sospechosas desde un usuario de bajo privilegio
   → notify-alert: avisa al equipo
   → revoke-credentials: desactiva las credenciales del usuario comprometido
```

**¿Qué siente el atacante?**
Sus credenciales dejan de funcionar antes de que pueda completar la escalada.

---

## Ataque 4 — Exfiltración de Datos (EXFILTRATION)

**¿Qué intenta el atacante?**
Ya tiene acceso y quiere llevarse datos. Empieza a copiar archivos de buckets S3 hacia afuera — ya sea descargándolos o replicándolos a otra cuenta de AWS que controla.

**¿Qué ve el atacante?**
Los datos se están transfiriendo. Desde su perspectiva, está logrando su objetivo.

**¿Qué registra AWS?**
Operaciones masivas de `GetObject` o `CopyObject` desde S3, especialmente hacia IPs o cuentas externas, generan un volumen de eventos anormal.

**¿Cómo responde el sistema?**
```
Detecta: transferencia masiva de datos desde S3
   → notify-alert: avisa al equipo
   → isolate-instance: aísla el recurso comprometido, detiene la transferencia
```

**¿Qué siente el atacante?**
La transferencia se corta. El recurso queda inaccesible y en cuarentena.

---

## Ataque 5 — Escaneo de Puertos (PORT_SCAN)

**¿Qué intenta el atacante?**
Antes de atacar directamente, quiere saber qué servicios están expuestos — qué puertos están abiertos, qué versiones corren, qué superficie de ataque existe. Es como caminar alrededor de un edificio buscando ventanas abiertas.

**¿Qué ve el atacante?**
Está recopilando información pasivamente. Cree que este tipo de reconocimiento no genera alertas.

**¿Qué registra AWS?**
Los VPC Flow Logs registran conexiones rechazadas o intentos a múltiples puertos desde la misma IP en poco tiempo.

**¿Cómo responde el sistema?**
```
Detecta: múltiples conexiones a distintos puertos desde la misma IP
   → notify-alert: avisa al equipo
   → block-ip: registra la IP antes de que el atacante pase a la siguiente fase
```

**¿Qué siente el atacante?**
Su IP queda bloqueada en la etapa de reconocimiento, antes de que pueda intentar el ataque real.

---

## Resumen: atacante vs. sistema

| Ataque | Lo que intenta el atacante | Cómo lo detecta el sistema | Cómo responde |
|--------|---------------------------|---------------------------|---------------|
| Fuerza bruta | Adivinar contraseña | +5 intentos fallidos / IP | Avisa + bloquea IP |
| Credencial robada | Usar keys filtradas | Key usada desde IP desconocida | Avisa + desactiva key |
| Escalada de privilegios | Darse más permisos | Comandos IAM fuera de perfil | Avisa + desactiva credenciales |
| Exfiltración | Robar datos de S3 | Transferencia masiva inusual | Avisa + aísla recurso |
| Escaneo de puertos | Reconocer la infraestructura | Múltiples puertos desde misma IP | Avisa + bloquea IP |

---

## Lo que el atacante nunca ve

Desde la perspectiva del atacante, AWS es solo una API o una página web. No ve:

- Que CloudTrail registra cada uno de sus movimientos.
- Que una Lambda está leyendo esos registros en tiempo real.
- Que en segundos, un equipo recibió una alerta con su IP y el detalle de lo que intentó.
- Que sus credenciales fueron desactivadas o su recurso aislado mientras todavía estaba conectado.

Esa invisibilidad del sistema de respuesta es precisamente su ventaja.
