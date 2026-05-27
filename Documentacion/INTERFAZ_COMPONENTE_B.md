VARIABLES REQUERIDAS POR INCIDENTE — COMPONENTE B (Aarón)
Tesis: Sistema de Detección y Respuesta ante Incidentes en AWS


Para cada incidente detectado, Aarón debe extraer las siguientes variables de sus
consultas y publicarlas en la cola de incidentes en formato JSON.


════════════════════════════════════════════════════════════
INCIDENTE 1: FUERZA BRUTA  (BRUTE_FORCE)
════════════════════════════════════════════════════════════

Qué es:   5 o más intentos fallidos de login (ConsoleLogin) desde la misma IP
          en una ventana de 5 minutos.

Fuente:   CloudTrail  →  evento ConsoleLogin con errorCode = AccessDenied

Variables que Aarón debe extraer y enviar:

    Variable            Obligatorio   Descripción                        Ejemplo
    ──────────────────  ───────────   ────────────────────────────────   ─────────────────────────────
    incident_type       SI            Nombre fijo del incidente           "BRUTE_FORCE"
    severity            SI            Nivel de gravedad                   "HIGH"
    sourceIPAddress     SI            IP desde donde llegaron los ataques "185.220.101.5"
    affectedResource    SI            Usuario objetivo del ataque         "iam:user/dev-operator"
    s3_log_key          SI            Ruta del log en S3                  "cloudtrail/2026/05/19/.../archivo.json"
    timestamp           SI            Fecha y hora de detección           "2026-05-19T00:01:15Z"
    event_count         SI            Número de eventos analizados        10
    failed_attempts     Opcional      Intentos fallidos detectados        10
    detection_window    Opcional      Ventana de tiempo analizada         "5 minutes"

Origen de cada variable en la query:

    sourceIPAddress   →   r.sourceIPAddress
    affectedResource  →   "iam:user/" + r.userIdentity.userName
    failed_attempts   →   COUNT(*)
    timestamp         →   MAX(r.eventTime)


════════════════════════════════════════════════════════════
INCIDENTE 2: ESCANEO DE PUERTOS  (PORT_SCAN)
════════════════════════════════════════════════════════════

Qué es:   La misma IP genera conexiones rechazadas (REJECT) hacia 10 o más
          puertos distintos en una ventana de 5 minutos.

Fuente:   VPC Flow Logs  →  registros con acción = REJECT

Variables que Aarón debe extraer y enviar:

    Variable              Obligatorio   Descripción                           Ejemplo
    ────────────────────  ───────────   ───────────────────────────────────   ─────────────────────────────
    incident_type         SI            Nombre fijo del incidente              "PORT_SCAN"
    severity              SI            Nivel de gravedad                      "MEDIUM"
    sourceIPAddress       SI            IP que realizó el escaneo              "185.220.101.5"
    affectedResource      SI            VPC o subred escaneada                 "vpc/vpc-3c0db7f4"
    s3_log_key            SI            Ruta del log en S3                     "vpc-flow/2026/05/19/.../archivo.log"
    timestamp             SI            Fecha y hora de detección              "2026-05-19T00:01:15Z"
    event_count           SI            Número de eventos analizados           15
    rejected_connections  Opcional      Conexiones rechazadas detectadas        15
    scanned_ports_count   Opcional      Puertos distintos escaneados            12

Origen de cada variable en la query:

    sourceIPAddress       →   srcAddr  (campo de VPC Flow Logs)
    affectedResource      →   ID de la VPC afectada
    rejected_connections  →   COUNT(*) donde acción = REJECT
    scanned_ports_count   →   COUNT(DISTINCT dstPort)


════════════════════════════════════════════════════════════
INCIDENTE 3: ESCALADA DE PRIVILEGIOS  (PRIVILEGE_ESCALATION)
════════════════════════════════════════════════════════════

Qué es:   Un usuario ejecuta acciones críticas de IAM que no le corresponden:
          adjuntar políticas de administrador, crear access keys, modificar roles.

Fuente:   CloudTrail  →  eventos IAM: AttachUserPolicy, AttachRolePolicy,
          CreateAccessKey, PutUserPolicy, AddUserToGroup

Variables que Aarón debe extraer y enviar:

    Variable            Obligatorio   Descripción                              Ejemplo
    ──────────────────  ───────────   ──────────────────────────────────────   ──────────────────────────────────
    incident_type       SI            Nombre fijo del incidente                 "PRIVILEGE_ESCALATION"
    severity            SI            Nivel de gravedad                         "CRITICAL"
    sourceIPAddress     SI            IP desde donde se hizo la escalada        "185.220.101.5"
    affectedResource    SI  *         Usuario que realizó las acciones          "iam:user/dev-operator"
    s3_log_key          SI            Ruta del log en S3                        "cloudtrail/2026/05/19/.../archivo.json"
    timestamp           SI            Fecha y hora de detección                 "2026-05-19T00:01:15Z"
    event_count         SI            Número de eventos analizados              3
    suspicious_actions  Opcional      Lista de acciones IAM detectadas          ["AttachUserPolicy", "CreateAccessKey"]
    target_policy_arn   Opcional      Política que intentó adjuntarse           "arn:aws:iam::aws:policy/AdministratorAccess"

Origen de cada variable en la query:

    sourceIPAddress     →   r.sourceIPAddress
    affectedResource    →   "iam:user/" + r.userIdentity.userName
    suspicious_actions  →   lista de r.eventName detectados
    target_policy_arn   →   r.requestParameters.policyArn

    * IMPORTANTE: affectedResource debe escribirse EXACTAMENTE como
      "iam:user/NOMBRE_DEL_USUARIO" — ese prefijo es obligatorio.


════════════════════════════════════════════════════════════
INCIDENTE 4: FUGA DE CREDENCIALES  (CREDENTIAL_LEAK)
════════════════════════════════════════════════════════════

Qué es:   Credenciales de un usuario legítimo son utilizadas desde una IP
          externa o inusual (fuera del rango normal de la organización).

Fuente:   CloudTrail  →  llamadas a la API (GetCallerIdentity u otras) desde
          una IP que no pertenece al rango de IPs internas conocidas.

Variables que Aarón debe extraer y enviar:

    Variable            Obligatorio   Descripción                                  Ejemplo
    ──────────────────  ───────────   ──────────────────────────────────────────   ──────────────────────────────────
    incident_type       SI            Nombre fijo del incidente                     "CREDENTIAL_LEAK"
    severity            SI            Nivel de gravedad                             "CRITICAL"
    sourceIPAddress     SI            IP externa desde donde se usaron las creds    "185.220.101.5"
    affectedResource    SI  *         Usuario cuyas credenciales fueron filtradas    "iam:user/external-contractor"
    s3_log_key          SI            Ruta del log en S3                            "cloudtrail/2026/05/19/.../archivo.json"
    timestamp           SI            Fecha y hora de detección                     "2026-05-19T00:01:15Z"
    event_count         SI            Número de eventos analizados                  1
    service_accessed    Opcional      Servicio al que se accedió                    "sts.amazonaws.com"
    unusual_region      Opcional      Región inusual desde donde se accedió         "ap-southeast-1"

Origen de cada variable en la query:

    sourceIPAddress     →   r.sourceIPAddress
    affectedResource    →   "iam:user/" + r.userIdentity.userName
    service_accessed    →   r.eventSource
    unusual_region      →   r.awsRegion

    * IMPORTANTE: affectedResource debe escribirse EXACTAMENTE como
      "iam:user/NOMBRE_DEL_USUARIO" — ese prefijo es obligatorio.


════════════════════════════════════════════════════════════
INCIDENTE 5: EXFILTRACIÓN DE DATOS  (EXFILTRATION)
════════════════════════════════════════════════════════════

Qué es:   Descarga masiva de archivos desde S3. Más de 50 operaciones GetObject
          desde la misma IP en el lapso de una hora.

Fuente:   CloudTrail  →  eventos S3: eventName = GetObject

Variables que Aarón debe extraer y enviar:

    Variable            Obligatorio   Descripción                              Ejemplo
    ──────────────────  ───────────   ──────────────────────────────────────   ──────────────────────────────────
    incident_type       SI            Nombre fijo del incidente                 "EXFILTRATION"
    severity            SI            Nivel de gravedad                         "HIGH"
    sourceIPAddress     SI            IP desde donde se descargaron los datos   "185.220.101.5"
    affectedResource    SI            Recurso comprometido (instancia o bucket) "ec2:instance/i-0abc123def456"
    s3_log_key          SI            Ruta del log en S3                        "cloudtrail/2026/05/19/.../archivo.json"
    timestamp           SI            Fecha y hora de detección                 "2026-05-19T00:01:15Z"
    event_count         SI            Número de eventos analizados              55
    total_downloads     Opcional      Archivos descargados detectados            55
    affected_bucket     Opcional      Bucket S3 del que se extrajeron datos      "prod-data-bucket"
    first_access        Opcional      Primer acceso detectado                    "2026-05-18T23:00:00Z"
    last_access         Opcional      Último acceso detectado                    "2026-05-18T23:58:00Z"

Origen de cada variable en la query:

    sourceIPAddress     →   r.sourceIPAddress
    affectedResource    →   "ec2:instance/" + ID de la instancia origen
    total_downloads     →   COUNT(*)
    affected_bucket     →   extraído de r.resources[0].ARN
    first_access        →   MIN(r.eventTime)
    last_access         →   MAX(r.eventTime)


════════════════════════════════════════════════════════════
RESUMEN RÁPIDO — VARIABLES CRÍTICAS POR INCIDENTE
════════════════════════════════════════════════════════════

    Incidente              Dato más importante     Formato de affectedResource
    ─────────────────────  ─────────────────────   ──────────────────────────────────────
    BRUTE_FORCE            sourceIPAddress          "iam:user/<nombre_usuario>"
    PORT_SCAN              sourceIPAddress          "vpc/<id>" o "subnet/<id>"
    PRIVILEGE_ESCALATION   affectedResource *       "iam:user/<nombre_usuario>"
    CREDENTIAL_LEAK        affectedResource *       "iam:user/<nombre_usuario>"
    EXFILTRATION           affectedResource         "ec2:instance/<id>" o "s3:::<bucket>"

    * Para estos dos incidentes, affectedResource debe incluir el prefijo
      "iam:user/" obligatoriamente.


════════════════════════════════════════════════════════════
CÓMO PUBLICAR EL MENSAJE EN LA COLA
════════════════════════════════════════════════════════════

Una vez detectado el incidente y extraídas las variables, Aarón publica
el mensaje en la cola SQS con el siguiente código:

    import boto3, json

    sqs = boto3.client(
        "sqs",
        endpoint_url="http://localhost:4566",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test"
    )

    payload = {
        "incident_type":    "BRUTE_FORCE",
        "severity":         "HIGH",
        "sourceIPAddress":  "IP extraída de la query",
        "affectedResource": "iam:user/nombre_extraído_de_la_query",
        "s3_log_key":       "ruta del log en S3",
        "event_count":      10,
        "timestamp":        "2026-05-19T00:01:15Z"
    }

    sqs.send_message(
        QueueUrl="http://localhost:4566/000000000000/tesis-incident-queue",
        MessageBody=json.dumps(payload)
    )
