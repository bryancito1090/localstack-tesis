# Forgejo Actions y proteccion de develop

Ansible se entrega desde `feature/1-ansible-portal-cloudwatch`, asociada al Issue #1 en Forgejo, hacia `develop`. No se hace push directo a `develop` o `main`.

El workflow [security.yml](../.forgejo/workflows/security.yml) usa un runner `ubuntu-latest`, Linux x86_64 o ARM64 con Node compatible con Actions y acceso HTTPS a GitHub, PyPI, Galaxy y los registros Terraform:

| Job | Comprobacion |
|---|---|
| `gitflow` | Rama, destino `develop`, `Closes #issue`, milestone y etiqueta de tipo iguales en Issue/PR; todos los asuntos de commits entre base y HEAD de 10 a 72 caracteres. |
| `ansible` | Coleccion AWS, syntax-check, ansible-lint y pruebas de autenticacion, bloqueo, eventos, inventario y reglas de integracion. |
| `terraform` | Formato, inicializacion sin backend y validacion, sin plan/apply ni credenciales AWS. |
| `secretos` | Gitleaks con reglas oficiales y exclusiones locales sobre commits nuevos, con salida redactada. |

Los PR se validan sobre el SHA de origen. Los pushes permiten revisar codigo antes del PR; la comprobacion de metadatos requiere el PR. No hay filtros por archivos que dejen checks obligatorios sin ejecutar.

## Configuracion

En **Settings → Repository → Advanced Settings** habilita Actions. En **Settings → Actions → Runners** debe haber un runner conectado con etiqueta `ubuntu-latest`. Si usa otra etiqueta, ajusta `runs-on` o agrega la etiqueta equivalente al runner. Referencia: [Forgejo Actions 1.21](https://forgejo.org/docs/v1.21/user/actions/).

En **Settings → Branches**, protege `develop`:

- Deshabilitar push directo y force push.
- Exigir los cuatro contextos del evento `pull_request` del workflow.
- Bloquear merge con rama desactualizada o revisiones que soliciten cambios.
- Descartar aprobaciones obsoletas.

Los contextos obligatorios configurados son `Validacion / gitflow (pull_request)`, `Validacion / ansible (pull_request)`, `Validacion / terraform (pull_request)` y `Validacion / secretos (pull_request)`. La proteccion se configura en Forgejo: el YAML por si solo no bloquea merges. Los administradores conservan las facultades del servidor; el flujo ordinario debe respetar checks y PR. Protege tambien `main` contra push directo; los cortes de version siguen el flujo de release documentado.

## Uso diario

1. Crear Issue con milestone y una etiqueta `type::feature`, `type::bug` o `type::chore`.
2. Crear desde `forgejo/develop` la rama `<feature|bugfix|chore>/<issue>-slug`.
3. Usar asuntos de commits descriptivos de 10 a 72 caracteres.
4. Publicar en `forgejo` y abrir PR hacia `develop` con `Closes #issue`.
5. Asignar el mismo milestone y etiqueta de tipo, y solicitar revisor cuando exista otro colaborador.
6. Esperar los cuatro checks del ultimo commit y revisar el diff antes de integrar.

En Forgejo 1.21, editar etiquetas o milestone puede no iniciar otra ejecucion. Completa los metadatos al crear el PR o relanza el workflow tras editarlos. No se publican comentarios automaticos ni se almacenan tokens personales o credenciales AWS en el YAML; el token efimero solo lee metadatos.

El runner anuncia internamente `http://forgejo:3000`, que no resuelve desde los contenedores de jobs. El checkout y las consultas de metadatos usan explicitamente `https://git.bryan-bano.com`; el runner debe poder alcanzar esa URL. No se desactiva la verificacion TLS.
