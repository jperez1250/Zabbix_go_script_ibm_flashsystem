zabbix-ibm-flashsystem-monitor/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   ├── workflows/
│   │   ├── go-build.yml
│   │   └── release.yml
│   └── PULL_REQUEST_TEMPLATE.md
├── src/
│   ├── main.go                          ✅ GO - Entry point
│   ├── go.mod                           ✅ GO - Module definition
│   ├── go.sum                           ✅ GO - Dependency hashes
│   └── lib/
│       ├── ssh_client.go                ✅ GO - SSH seguro con hardening
│       ├── cli_commands.go              ✅ GO - Whitelist de comandos CLI
│       ├── lld_builder.go               ✅ GO - Constructor JSON LLD
│       ├── metrics.go                   ✅ GO - Funciones de métricas
│       └── security.go                  ✅ GO - Logging y auditoría
├── config/
│   ├── zabbix.json.example              ✅ Config no sensible
│   └── secrets.env.example              ✅ Template para secretos
├── templates/
│   └── zabbix_template_ibm_flashsystem_5045.xml  ⏳ Pendiente
├── docs/
│   ├── INSTALL_RHEL9.md                 ⏳ Pendiente
│   ├── SECURITY.md                      ⏳ Pendiente
│   ├── TROUBLESHOOTING.md               ⏳ Pendiente
│   ├── COMMANDS_REFERENCE.md            ⏳ Pendiente
│   └── METRICS_REFERENCE.md             ⏳ Pendiente
├── scripts/
│   ├── install.sh                       ⏳ Pendiente
│   ├── uninstall.sh                     ⏳ Pendiente
│   ├── test_connection.sh               ⏳ Pendiente
│   └── rotate_ssh_key.sh                ⏳ Pendiente
├── .gitignore                           ✅ Excluye binarios y secretos
├── .golangci.yml                        ✅ Linter de Go
├── LICENSE                              ✅ Apache 2.0
├── README.md                            ⏳ Pendiente (actualizar sin Python)
├── CHANGELOG.md                         ⏳ Pendiente
├── CONTRIBUTING.md                      ⏳ Pendiente
└── Makefile                             ⏳ Pendiente (build Go)