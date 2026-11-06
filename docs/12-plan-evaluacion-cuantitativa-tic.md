# 12. Plan de evaluación cuantitativa del TIC

## 1. Propósito y alcance

Evaluar con datos reproducibles el sistema de detección y respuesta ante incidentes en AWS. Las preguntas son: ¿cuánto tarda el portal?, ¿cuánto tarda en detectarse un incidente elegible?, ¿cuánto tarda la contención efectiva?, ¿con qué frecuencia se detecta y contiene correctamente?, ¿qué recursos consume la automatización?

Este documento es un **protocolo propuesto**, no una campaña ejecutada ni una afirmación de rendimiento. Los resultados funcionales del despliegue no sustituyen una muestra estadística. Los objetivos numéricos de la sección 9 deben acordarse con el tutor, ajustarse durante el piloto y congelarse antes de la campaña principal.

Las afirmaciones narrativas de documentos anteriores, como respuesta «en segundos», entrega garantizada o un costo mensual fijo, se tratarán como expectativas por contrastar. Solo se incorporarán a las conclusiones los resultados medidos, su cobertura y sus limitaciones.

Separar los resultados de los componentes A (telemetría), B (detección) y C (respuesta automatizada, componente principal de Bryan). Una prueba de C puede comenzar en su cola dedicada; esa prueba no mide la detección ni la entrega previa de CloudTrail.

## 2. Qué se puede medir hoy

La referencia es el código ejecutado, junto con el commit, las variables y los recursos de cada ensayo:

| Evidencia existente | Qué permite medir | Límite actual |
|---|---|---|
| `curl` desde el cliente | Código HTTP, conexión, primer byte y tiempo total | Depende de la red/VPN del cliente; cada proceso crea su propia conexión. |
| Nginx: `request_time`, `uri`, `status`, `source_ip` | Tiempo en Nginx y distribución por ruta/estado | No incluye todo el trayecto cliente-servidor y no registra un identificador por petición. |
| Portal: `event_type`, `timestamp_utc`, `user_agent` | Origen temporal de eventos de autenticación | No guarda todavía `run_id`/`trial_id` como campos propios. |
| Detector: S3 y DynamoDB `created_at`, `incident_id` | Momento en que comienza `save_incident()` | `created_at` se obtiene antes de guardar S3/DynamoDB y despachar SQS; no es la finalización de esas operaciones. |
| CloudWatch `AWS/Lambda` y registros `REPORT` | Invocaciones, errores de función, duración y memoria | Una invocación puede procesar varios eventos; duración Lambda no es tiempo de respuesta del sistema. |
| S3 `responses/block-ip/` y `responses/revoke-credentials/` | Identificador, resultado declarado y evidencia de acción | El `timestamp` del playbook se toma antes de ejecutar las llamadas IAM/NACL. No sirve como tiempo exacto de contención finalizada. |
| `notify-alert`: `detectedAt`, `respondedAt`, `status` | Evidencia inicial de preparación de una notificación | Se construye y guarda antes de SES/SNS; `NOTIFIED` no demuestra entrega al destinatario. |
| Telegram: respuesta de API y logs | Aceptación de una solicitud por la API | Falta persistir la aceptación con tiempo e identidad correlacionada; no prueba que una persona haya leído la tarjeta. |
| Terraform y recap de Ansible | Duración operativa, errores, cambios e idempotencia | No mide por sí solo el desempeño de detección/contención. |

En el código actual `TesisIR` publica un contador cuyo **nombre es el tipo de incidente**, por ejemplo `BRUTE_FORCE`, sin dimensiones. No existen todavía métricas personalizadas de MTTD/MTTC ni una métrica única `IncidentDetected` con dimensiones por severidad.

Los playbooks capturan algunos errores y pueden devolver una ejecución Lambda técnicamente correcta aunque falle una acción. Por eso `AWS/Lambda Errors = 0` no demuestra éxito de negocio. Deben comprobarse el resultado, la evidencia y una prueba independiente del efecto.

## 3. Relojes y definiciones temporales

Guardar UTC en ISO 8601 con zona explícita y, para la futura instrumentación, `epoch_ms`. Ecuador UTC−05:00 queda para presentación. Usar reloj monotónico para intervalos medidos dentro de un mismo proceso; comprobar sincronización del controlador y EC2 y registrar su desviación. No corregir silenciosamente duraciones negativas: son un problema de reloj, correlación o datos.

| Marca | Definición operativa |
|---|---|
| `t_first` | Primer evento del ensayo. |
| `t_eligible` | Evento que completa la condición de la regla: quinto fallo, décimo puerto distinto o llamada IAM pertinente, según el caso. |
| `t_log` | `@ingestionTime` del registro que contiene el evento elegible. |
| `t_detect` | `created_at` al entrar en `save_incident()`, usado como aproximación documentada de detección. |
| `t_persisted` | Confirmación de persistencia del incidente; requiere instrumentación adicional. |
| `t_queue` | Confirmación de `SendMessage`, con `MessageId`; requiere instrumentación adicional. |
| `t_worker` | Inicio del procesamiento del mensaje por el playbook; requiere instrumentación adicional. |
| `t_action` | Respuesta satisfactoria de la API que aplica la acción, incluyendo su identificador de solicitud. |
| `t_last_allowed` | Última sonda independiente que todavía tuvo acceso. |
| `t_verified` | Primera sonda independiente que comprueba el bloqueo esperado. |
| `t_notify_api` | Confirmación satisfactoria de SES/SNS/Telegram, separada por canal y tipo de mensaje. |
| `t_client` | Recepción comprobada en el cliente de correo o chat. Solo se usa cuando existe evidencia de recepción. |

Para reglas por conteo se deben registrar `t_first` y `t_eligible`: incluir la acumulación de cinco eventos en la latencia de procesamiento cambia la interpretación del resultado.

Las ventanas del detector son **bloques de tiempo** calculados mediante división del epoch, no ventanas deslizantes exactas. En varias reglas el contador usa el tiempo de procesamiento. Ensayar explícitamente cruces de frontera de ventana y entrega tardía/fuera de orden. El texto `timestamp_utc` generado para `PORT_SCAN` es del procesamiento; conservar también `raw_event.start/end` y los tiempos del generador. No usar ese timestamp como inicio real del escaneo.

CloudTrail y VPC Flow Logs incorporan entrega y agregación asíncronas. El proyecto configura `max_aggregation_interval = 60` para Flow Logs; eso no significa entrega garantizada en 60 segundos. AWS describe entrega de Flow Logs a CloudWatch típicamente en minutos y entrega de CloudTrail a S3 también con demora no garantizada. Medir cada fuente por separado. [Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html), [CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/get-and-view-cloudtrail-log-files.html).

## 4. Matriz de métricas

Las restas entre timestamps se expresan en segundos; `request_time` y los tiempos de curl están en segundos y se multiplican por 1000 para presentar milisegundos.

| Métrica | Definición/fórmula | Fuente y presentación |
|---|---|---|
| Respuesta HTTP | `1000 × time_total`; primer byte `1000 × time_starttransfer` | Cliente: n, mediana, p95, mínimo, máximo y fallos, separados por ruta/red/carga. |
| Procesamiento web | `1000 × request_time` | Nginx: p50/p95; no sustituye el tiempo HTTP del cliente. |
| Éxito HTTP | `respuestas esperadas / intentos × 100` | Distinguir fallo de transporte, 5xx, 401/403 esperados y 302 esperado del login. |
| Rendimiento HTTP | `peticiones finalizadas / duración real del bloque` | Solicitudes/s; indicar concurrencia y clientes. No obtenerlo sumando duraciones de solicitudes concurrentes. |
| Tiempo de ingesta | `t_log − t_eligible` | Por fuente; requiere correlacionar el evento real y controlar relojes. |
| Detección desde inicio | `t_detect − t_first` | Incluye acumulación de la condición. Media (MTTD desde inicio), mediana y p95. |
| Detección tras umbral | `t_detect − t_eligible` | MTTD posumbral; no mezclar con la definición anterior. |
| Espera en cola | `t_worker − t_queue` | Por cola/playbook; pendiente de instrumentación. |
| Ejecución de acción | `t_action − t_worker` | Por playbook; pendiente de instrumentación. |
| Contención desde detección | `t_verified − t_detect` | MTTC, mediana y p95; comprobar efecto y tipo de acción. |
| Contención de extremo a extremo | `t_verified − t_eligible` | Medida principal para respuesta automatizada; reportar también desde `t_first`. |
| Notificación aceptada | `t_notify_api − t_detect` | SES, SNS y Telegram separados; SNS no equivale a entrega al usuario. |
| Recepción en cliente | `t_client − t_detect` | Solo con observación del destinatario; de otro modo `NO_OBSERVABLE`. |
| Éxito de contención | `ensayos con efecto confirmado / ensayos que requerían contención × 100` | Excluir `EXFILTRATION` del denominador de bloqueo, pues actualmente solo notifica. Mantener los intentos fallidos en el denominador. |
| Calidad de detección | Precisión, recall, FPR y F1, definidos abajo | Unidades experimentales etiquetadas antes de ejecutar. |
| Duplicación | `max(0, incidentes de la misma clase por ensayo − 1)` | Por clase/ventana; contar separadamente reintentos de cada playbook/canal. |
| Salud de ejecución | `Errors/Invocations × 100`, `Throttles`, p95 `Duration`, memoria | CloudWatch `AWS/Lambda`; incluir evidencia de fallos de negocio aparte. |
| Reproducibilidad | Duración de despliegue/configuración, fallos y `% de reaplicaciones con changed=0` | Terraform/Ansible, distinguiendo despliegue inicial, actualización y reaplicación sin deriva. |
| Consumo | Horas EC2, bytes ingeridos, GB consultados, solicitudes y costo incremental por ensayo | Datos de uso/facturación; reportar moneda, fecha y créditos/impuestos por separado. |

No llamar simplemente **MTTR** a todos los intervalos. En este TIC se propone **MTTC = tiempo hasta contención**. La recuperación completa del servicio o la resolución del incidente son desenlaces distintos y requieren otra marca final explícita.

`Duration` de Lambda excluye el arranque en frío; separar inicialización observada en logs y ejecuciones calientes. Los indicadores aproximados de SQS sirven para diagnosticar acumulación, no para medir exactamente una espera individual. [Lambda](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html), [métricas SQS](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-available-cloudwatch-metrics.html).

### Matriz de confusión

La unidad es **un ensayo**, no cada línea de log ni cada mensaje. Para evaluar una clase: TP = ensayo elegible detectado con el tipo correcto dentro del plazo; FN = ensayo elegible sin ese resultado dentro del plazo; FP = detección de esa clase en un ensayo benigno para esa clase; TN = ensayo benigno sin esa detección. Registrar las confusiones entre clases: pueden contribuir a FN de la esperada y FP de la predicha. Para evaluación binaria adicional, usar únicamente presencia/ausencia de cualquier incidente, en una tabla distinta.

```text
precision = TP / (TP + FP)
recall    = TP / (TP + FN)
FPR       = FP / (FP + TN)
F1        = 2 × precision × recall / (precision + recall)
```

Un denominador cero produce `NO_APLICA`, no 0 ni 100 %. El tráfico de Internet ajeno al experimento queda `NO_ETIQUETADO`: una alerta de un origen desconocido no demuestra por sí sola un falso positivo. Incluir además falsos bloqueos/revocaciones como daños de respuesta, aunque el tipo de detección fuese otro.

## 5. Diseño experimental

### Fases

| Fase | Protocolo propuesto | Resultado esperado del trabajo |
|---|---|---|
| Preparación | Congelar commit/configuración, sincronizar relojes, comprobar red y canales, preparar identidades y recuperación. | Manifiesto y lista de precondiciones. |
| Piloto | 5 ensayos maliciosos y 5 benignos por escenario; HTTP: 10 solicitudes por ruta. | Detectar fallos de medición y estimar tiempos, costo y plazo de observación. No mezclarlo con la campaña principal. |
| Principal | Por escenario: 30 ensayos positivos y 30 negativos, distribuidos en tres bloques de 10 de cada clase. | 300 ensayos etiquetados para los cinco escenarios, si todos están habilitados; no son 300 peticiones. |
| HTTP | Por ruta `/health` y `/login` GET: 3 bloques de 100 solicitudes secuenciales, luego repetir opcionalmente con concurrencia 5 y 10, por separado. | 600 solicitudes en el nivel secuencial. Registrar 5 calentamientos por celda fuera de los estadísticos principales. |
| Comparación C | Para `block-ip` y `revoke-credentials`: 10 pares manual/automatizado como piloto, ampliables a 30 pares por acción. | Comparación pareada del mismo efecto con inicio común y operador entrenado. |
| Análisis | Calcular resultados por escenario, fuente, bloque, modo y estado del canal. | Tablas, gráficas y límites de validez. |

Los tamaños anteriores son un presupuesto de trabajo propuesto, no un cálculo de potencia estadística. Si la campaña cambia tras el piloto, documentar la nueva versión y su justificación antes de medir. El aumento de concurrencia es una fase separada: la aplicación usa `HTTPServer`, sin capacidad de paralelismo de aplicación demostrada, por lo que se debe observar su saturación y no asumir escalabilidad.

Registrar región, instancia/AMI, memoria de Lambdas, timeouts, colas, intervalos de Flow Logs, umbrales efectivos, versiones, fecha UTC, red/VPN del generador, reloj, identidad seudonimizada y estado SES/DKIM. Un cambio de red crea un nuevo bloque: sus tiempos HTTP no se agregan como si procedieran de la misma conexión.

### Escenarios y oráculo independiente

| Escenario | Caso positivo | Control negativo y verificación |
|---|---|---|
| `BRUTE_FORCE` | 5 fallos desde una IP de prueba en la misma ventana del detector. | Login válido y hasta 4 fallos con estado aislado; comprobar umbral y tipo. Contención: nueva conexión desde el origen bloqueado y sonda de salud desde otro origen. |
| `PORT_SCAN` | Tráfico rechazado a 10 puertos distintos en la ventana. | 9 puertos distintos y repeticiones de un mismo puerto en ensayo aislado. Registrar la captura real; la implementación actual no excluye explícitamente las IP autorizadas en esta regla. |
| `PRIVILEGE_ESCALATION` | Operación IAM de la lista crítica ejecutada por actor desechable fuera de la exención administrativa. | Administrador autorizado desde IP permitida y operación no crítica. El código detecta operaciones de la lista, no un análisis semántico completo del incremento de privilegios. El actor, no necesariamente el usuario objetivo de la API, es quien se señala para contención. |
| `CREDENTIAL_LEAK` | Identidad desechable llama una API contemplada por la regla desde una IP fuera de la lista permitida. | Esa identidad desde IP permitida. Verificar que una acción previamente autorizada sobre un recurso de prueba deja de funcionar. |
| `EXFILTRATION` | Habilitar S3 Data Events y alcanzar el umbral de `GetObject` del bucket sensible. | Umbral menos uno y otro bucket en ensayos aislados. El código usa `>= 50` por defecto, no estrictamente `> 50`; registrar el valor efectivo. El desenlace actual es alerta/evidencia, sin bloqueo de descarga. |

La etiqueta se fija mediante el guion del generador y su evidencia, antes de leer las alertas. Para reglas por ventana, `t_eligible` de la prueba real puede diferir del instante en que el consumidor alcanza el umbral debido al orden de entrega. Conservar ambas referencias cuando se instrumente el consumidor; no interpretar automáticamente esa diferencia como tiempo de cómputo.

### Aislamiento y recuperación entre ensayos

1. Mantener una sesión SSM y una identidad de recuperación independientes. No usar `admin-tesis`, root ni las claves del despliegue como víctima de revocación.
2. Registrar NACL, políticas, estado de la aplicación, contadores y deduplicación antes del ensayo. Usar una IP/identidad de laboratorio distinta del canal administrativo cuando sea posible. Una IP documental/privada será omitida por `block-ip` y no sirve para demostrar bloqueo real.
3. Aislar los contadores y deduplicación por origen/ventana. El detector de fuerza bruta cuenta por IP; cambiar solo el nombre de usuario no reinicia esa cuenta. Documentar espera de una ventana nueva o una limpieza controlada de las claves del ensayo; el TTL no es un reinicio inmediato garantizado.
4. Comprobar el efecto con sondas cada 1 s, registrando la última permitida y la primera denegada. El instante real queda acotado por ese intervalo, más tiempo de respuesta de la sonda; no afirmar precisión de milisegundos.
5. Para NACL, contrastar la regla exacta con una conexión nueva y un origen de control saludable. Un timeout aislado también puede ser un fallo de red, no evidencia suficiente de contención.
6. Para IAM, usar una acción que antes funcionaba sobre un objeto/bucket de laboratorio. `GetCallerIdentity` no demuestra ausencia de permisos: AWS permite obtener identidad incluso con una denegación explícita de esa operación. [Referencia AWS](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html).
7. Retirar únicamente la regla/política creada por el ensayo, verificar restauración y guardar evidencia antes/después. No eliminar bloqueos de terceros ni vaciar tablas/colas compartidas. Distinguir duplicados del mismo evento y llamadas nuevas de prueba.

### Plazos y ensayos incompletos

Valores iniciales para el **piloto**: 120 s desde el umbral para eventos web; 900 s para Flow Logs/CloudTrail; otros 120 s desde detección para confirmar contención o aceptación de notificación. Son límites de observación propuestos, no SLA de AWS ni resultados esperados garantizados. Revisarlos con el piloto y fijarlos para toda la campaña principal.

Al vencer un plazo, registrar `TIMEOUT` y el límite aplicado. Un incidente posterior queda como `LATE`; el ensayo sigue contando como fallo de detección o respuesta dentro del plazo. No eliminarlo de la tasa de éxito ni sustituir su tiempo por cero o por el deadline como si fuera una observación exacta. Distinguir fallo real, canal deshabilitado e instrumento roto: un ensayo inválido conserva su fila y una repetición usa otro identificador.

### Comparación manual/automatizada

Para aislar C, usar un incidente controlado idéntico como punto de partida y comenzar ambos métodos desde la entrega del incidente al operador o a la cola dedicada correspondiente. Alternar el orden manual/automático y restaurar el estado entre ambos. Registrar operador y entrenamiento; no comparar un operador no preparado con una automatización ya afinada.

```text
reduccion_pct = 100 × (tiempo_manual − tiempo_automatico) / tiempo_manual
```

Calcular por par y resumir distribución; si el manual es cero o no se observa el efecto, no fabricar el cociente. Los experimentos desde colas de playbooks se etiquetan `COMPONENTE_C`; los que nacen de actividad web/API/red se etiquetan `E2E`. No sumar sus latencias en una única media.

## 6. Instrumentación pendiente antes de medir tiempos internos exactos

Esto es trabajo posterior identificado por el plan; no se incorpora todavía a los servicios desplegados:

- Propagar `run_id` y `trial_id` desde generador a evento y desde detector a SQS/S3/playbooks; conservar `incident_id`, ID de evento CloudTrail/log, ID de mensaje y número de intento. Actualmente el detector copia campos seleccionados y no propaga cualquier campo adicional automáticamente.
- Emitir registros JSON de `incident_persisted`, `queue_send_accepted`, `worker_started`, `action_api_accepted`, `notification_api_accepted` y fallo de negocio. Registrar `epoch_ms` después de cada confirmación, sin sobrescribir la hora del evento original.
- Incluir `MessageId`/request ID, canal y estado real de cada envío. Un estado escrito antes del envío y una excepción capturada no equivalen a éxito.
- Registrar confirmaciones de SES/Telegram por separado de recepción en Gmail/chat. Si SES/DKIM están pendientes, etiquetar ese canal `NOT_READY` y declarar que la campaña de correo no está completa; no presentarlo como entrega exitosa.
- Mantener `run_id`/`incident_id` en logs y datasets; si se agregan métricas CloudWatch, usar dimensiones de baja cardinalidad como escenario y componente para evitar una serie por ensayo.

La instrumentación y los generadores deberán tener sus propios Issues/PR. Sin estos cambios se pueden medir HTTP, duración Lambda, el inicio aproximado de detección y el tiempo extremo a extremo observado por un cliente; no se puede descomponer con exactitud toda la espera SQS y cada etapa interna.

## 7. Recogida práctica y consultas

### Primera medición HTTP, sin provocar contención

Desde la raíz del proyecto, con el acceso de red ya actualizado:

```bash
PORTAL_URL=$(terraform -chdir=terraform-tesis-ir-secure-portal output -raw portal_url)
curl --silent --show-error --connect-timeout 5 --max-time 15 \
  --output /dev/null \
  --write-out 'http=%{http_code},connect_s=%{time_connect},ttfb_s=%{time_starttransfer},total_s=%{time_total}\n' \
  "$PORTAL_URL/health"
```

Conservar también el código de salida del proceso. HTTP `000` es ausencia de respuesta HTTP; un fallo no debe desaparecer porque se filtraron solo respuestas 200. Para el bloque secuencial, repetir 100 veces después de los calentamientos y escribir una fila por intento en la plantilla. No usar `--retry` ni `-L` en la medición base: mezclarían reintentos o redirecciones. El POST de login válido tiene 302 esperado; medir el dashboard en una petición posterior separada. [Tiempos y opciones curl](https://curl.se/docs/manpage.html).

El cronómetro HTTP y el tiempo Nginx tienen fronteras distintas. `$request_time` mide el procesamiento de la solicitud desde la perspectiva de Nginx. [Documentación Nginx](https://nginx.org/en/docs/http/ngx_http_log_module.html).

### Consultas CloudWatch Logs Insights

Seleccionar el grupo `/aws/ec2/tesis-ir-portal-app`, el intervalo UTC exacto y la instancia del manifiesto. Exportar resultados y texto de consulta. Ejemplo de tiempos web del servidor:

```text
filter @logStream like /nginx-access/
| filter uri = "/health" and source_ip != "127.0.0.1"
| fields request_time * 1000 as server_ms
| stats count() as n, avg(server_ms) as media_ms,
    pct(server_ms, 50) as p50_ms, pct(server_ms, 95) as p95_ms,
    max(server_ms) as max_ms by bin(5m)
```

Restringir además `source_ip` al cliente experimental si hay otros usuarios. El log actual no permite unir cada petición Nginx a `trial_id`; esta consulta es apoyo agregado del bloque, no una unión individual demostrada.

Eventos de autenticación:

```text
filter @logStream like /\/app$/
| filter event_type in ["login_success", "login_failed", "access_blocked"]
| stats count() as eventos by event_type
```

En el grupo de cada Lambda, para invocaciones y duración:

```text
filter @type = "REPORT"
| stats count() as invocaciones, avg(@duration) as media_ms,
    pct(@duration, 95) as p95_ms, max(@duration) as max_ms,
    max(@maxMemoryUsed) / 1024 / 1024 as memoria_max_mib
```

`@ingestionTime − @timestamp` es demora entre marcas de CloudWatch; en esta configuración el agente no extrae automáticamente la hora del JSON como timestamp del registro. Para medir desde el evento, correlacionar `timestamp_utc`/`eventTime` original fuera de la consulta o instrumentar epoch; no renombrar esa diferencia como MTTD. [Funciones y tiempos de Logs Insights](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax-operations-functions.html).

### Reaplicación de Ansible

```bash
time -p env ANSIBLE_CONFIG=ansible/ansible.cfg .venv/bin/ansible-playbook \
  -i ansible/inventory/hosts.yml ansible/playbook.yml
```

Guardar salida, tiempo de pared, commit y recap de cada ejecución. En una reaplicación sin deriva se espera `changed=0`, `failed=0`, `unreachable=0`. El mantenimiento con actualización de paquetes y los cambios deliberados constituyen otros escenarios.

## 8. Datos y análisis estadístico

Se incluyen plantillas **vacías**, sin resultados inventados, en [`plantillas-metricas/`](plantillas-metricas/):

- [`mediciones_http.csv`](plantillas-metricas/mediciones_http.csv): una fila por intento HTTP, con sus unidades, código de proceso y estado esperado.
- [`ensayos_incidentes.csv`](plantillas-metricas/ensayos_incidentes.csv): una fila por ensayo, incluidos negativos sin incidente, fallos, plazos y evidencia.
- [`eventos_medicion.csv`](plantillas-metricas/eventos_medicion.csv): una fila por etapa/intento/playbook/canal, enlazada al ensayo e incidente.

`run_id` identifica una ejecución de campaña; `trial_id`, un ensayo; `sample_id`, una solicitud. `expected_playbooks`, `detected_incident_ids` y `observed_incident_types` contienen arrays JSON escapados como celdas CSV. Usar UTC con `Z`/offset explícito; dejar vacío un dato ausente y explicar por qué en `notes` o `trial_status`. No rellenar tiempos no observados con cero.

`stage` utiliza: `trigger`, `eligible`, `log_ingested`, `detection_started`, `incident_persisted`, `queue_send_accepted`, `worker_started`, `action_api_accepted`, `probe_allowed`, `probe_denied`, `notification_api_accepted`, `client_received`. `clock_source` identifica cliente monotónico/UTC, EC2, Lambda o CloudWatch. Identificar además si el mensaje es alerta o mitigación mediante `component` y evidencia.

Guardar copias de las plantillas en un directorio local de resultados fuera del repositorio. Adjuntar un manifiesto con configuración efectiva y hashes SHA-256 de logs/CSV/exportaciones, consultas utilizadas y criterios de exclusión. No incluir credenciales, tokens de Telegram, cookies ni estados Terraform; seudonimizar usuarios/IP antes de publicar. Los hashes permiten detectar cambios posteriores, no certifican por sí solos autenticidad forense.

Para cada métrica informar `n_total`, `n_valido`, éxitos, fallos, tardíos, inválidos y faltantes. En las latencias observadas: media, mediana, mínimo, máximo, desviación estándar muestral y p95. Declarar la convención: ordenar y usar rango más cercano `x[ceil(p × n)]`, con índices desde 1. Con pocas muestras, p95 es inestable; no añadir p99 como conclusión principal de muestras pequeñas.

Para proporciones, presentar intervalo de confianza Wilson de 95 %, no solo el porcentaje puntual. No concluir fiabilidad de 99,9 % a partir de 30 ensayos sin fallos. Para comparar automatización/manual, conservar las diferencias pareadas; un intervalo bootstrap por **par/bloque**, con semilla y método declarados, es una opción de análisis posterior. La repetición en un mismo despliegue no convierte cada petición en una réplica independiente de una arquitectura nueva. [Intervalos de proporciones, NIST](https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm).

Entregables mínimos para el TIC: tabla de latencias por fuente/escenario; matriz de confusión y efectos indebidos; gráfico de distribución/ECDF de HTTP; comparación pareada de contención; tabla de consumo; anexos con datos crudos y manifiesto. Incluir fallos y variabilidad entre bloques/redes, no solo las ejecuciones más rápidas.

## 9. Hipótesis y criterios propuestos

| Criterio propuesto para acordar con el tutor | Cómo se decidirá |
|---|---|
| HTTP p95 ≤ 1000 ms con concurrencia 1 y ≥ 99 % de respuestas esperadas | Por ruta y red, con `n` y fallos; el límite no se traslada a concurrencias 5/10 automáticamente. |
| Recall ≥ 95 % y FPR ≤ 5 % por escenario | Estimación e intervalo Wilson; el objetivo puntual no equivale a demostrar que todo el intervalo cumple. |
| ≥ 95 % de contenciones requeridas verificadas dentro del plazo fijado | Exigir la sonda independiente; `SKIPPED`/`BLOCK_FAILED` no son contención exitosa. |
| Reducción de al menos 50 % en mediana de tiempo de contención respecto al procedimiento manual | Comparación pareada desde el mismo punto de partida, incluyendo incertidumbre y fallos. |
| 100 % de reaplicaciones sin deriva con cero cambios y cero fallos | Campaña de configuración declarada; no prometerlo para mantenimiento o modificaciones intencionales. |
| Trazabilidad completa en todos los ensayos válidos | `run_id`/`trial_id`, incidente cuando corresponda, tiempos, resultado y evidencia de acción. |

Estos son **objetivos de investigación propuestos**, no resultados obtenidos, compromisos de servicio ni límites tomados de AWS. Si el piloto sugiere otro límite, justificar el cambio y no ajustarlo retroactivamente para que los resultados aprueben.

## 10. Orden de ejecución recomendado

1. Restablecer acceso y comprobar `/health`, login válido, servicios y logs. Evitar inicialmente múltiples fallos de login que bloqueen la red de administración.
2. Completar manifiesto y piloto HTTP; medir la percepción del usuario y Nginx por separado.
3. Implementar la instrumentación pendiente y validar las uniones entre etapas con un ensayo controlado.
4. Ejecutar C desde sus colas dedicadas con recuperación independiente; medir contención efectiva.
5. Ejecutar los cinco escenarios E2E habilitados, sus controles y los bloques planificados. Si un canal o Data Events no está listo, declarar la cobertura faltante y completarla después.
6. Exportar evidencia, calcular métricas y contrastar hipótesis con el tutor. Este documento no autoriza lanzar automáticamente esa campaña ni modificar las identidades de administración.
