# A Jornada de Bia — v31.1

Home simplificada, estabilização de segurança e atualização do PWA, sem redesign visual.

## Estrutura
- `index.html`: estrutura da interface
- `css/style.css`: estilos extraídos sem alteração intencional
- `js/app.js`: lógica da aplicação
- `js/storage.js`: camada centralizada de persistência
- `js/security.js`: PIN com PBKDF2, sessão e bloqueio por tentativas
- `js/backup.js`: backup versionado, validação e integridade SHA-256
- `manifest.json`: configuração PWA
- `sw.js`: cache offline, versionamento e atualização do PWA

## Segurança
O PIN antigo em texto puro é migrado para PBKDF2-SHA-256 na primeira verificação. A sessão desbloqueada não fica mais persistida em `localStorage`.

Importante: como o app é client-side, isto não equivale a autenticação forte. Quem controla o dispositivo, o navegador ou os arquivos do app pode alterar o código. Para proteção de dados médicos contra um atacante local, a próxima etapa deve ser um cofre criptografado com chave derivada de uma senha do responsável e política clara de recuperação.

## Backups
- Backup completo
- Backup de configuração
- Backup automático de segurança antes da importação
- Validação de tamanho, estrutura, versão e integridade

## Publicação
Use GitHub Pages, HTTPS ou outro servidor web. Não abra o PWA diretamente com `file://`, pois Service Worker e APIs de origem segura dependem de uma origem web válida.
