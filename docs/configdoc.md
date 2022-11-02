# L3AFD Config Options Documentation

See [l3afd.cfg](https://github.com/l3af-project/l3afd/blob/main/config/l3afd.cfg) for a full example configuration.


```
[DEFAULT]

[l3afd]
pid-file: ./l3afd.pid
datacenter: dc
bpf-dir: /dev/shm
bpf-log-dir:
shutdown-timeout: 1s
http-client-timeout: 10s
max-ebpf-restart-count: 3
bpf-chaining-enabled: true
swagger-api-enabled: false
# PROD | DEV
environment: PROD
....
```

### Below is the detailed documentation for each field


## [l3afd]
| FieldName     | Default                | Description     | Required        |
| ------------- |------------------------| --------------- | --------------- |
|pid-file| `"/var/l3afd/l3afd.pid"` | The path to the l3afd.pid file which contains process id of L3afd | Yes |
|datacenter| `"dc"`                 | Name of Datacenter| Yes |
|bpf-dir| `"/dev/shm"`           | Absolute Path where eBPF packages are to be extracted | Yes |
|bpf-log-dir| `""`                   | Absolute Path for log files, which is passed to applications on the command line. L3afd does not store any logs itself.| No |
|kernel-major-version| `"5"`                  |Major version of the kernel required to run eBPF programs (Linux Only) | No |
|kernel-minor-version| `"1"`                  |Minor version of the kernel required to run eBPF programs (Linux Only)| No |
|shutdown-timeout| `"1s"`                 |Maximum amount of time allowed for l3afd to gracefully stop. After shutdown-timeout, l3afd will exit even if it could not stop applications.| No |
|http-client-timeout| `"10s"`                |Maximum amount of time allowed to get HTTP response headers when fetching a package from a repository| No |
|max-nf-restart-count| `"3"`                  |Maximum number of tries to restart eBPF applications if they are not running| No |
|bpf-chaining-enabled| `"true"`               |Boolean to set bpf-chaining. For more info about bpf chaining check [L3AF_KFaaS.pdf](https://github.com/l3af-project/l3af-arch/blob/main/L3AF_KFaaS.pdf)| Yes |
|swagger-api-enabled| `"false"`              |Whether the swagger API is enabled or not.  For more info see [swagger.md](https://github.com/l3af-project/l3afd/blob/main/docs/swagger.md)| No |
|environment| `"PROD"`               |If set to anything other than "PROD", mTLS security will not be checked| Yes |
|BpfMapDefaultPath| `"/sys/fs/bpf"`        |The base pin path for eBPF maps| Yes |

## [ebpf-repo]
| FieldName     | Default                    | Description     | Required |
| ------------- |----------------------------| --------------- |----------|
|url| `"file:///var/l3afd/repo"` |Default repository from which to download eBPF packages| Yes      |

## [web]

| FieldName          | Default       | Description     | Required |
|--------------------| ------------- | --------------- |----------|
| metrics-addr       |`"0.0.0.0:8898"`|Prometheus endpoint for pulling/scraping the metrics.  For more info about Prometheus see [prometheus.io](https://prometheus.io/) | Yes      |
| ebpf-poll-interval |`"30s"`|Periodic interval at which to scrape metrics using Prometheus| No       |
| n-metric-samples   |`"20"`|Number of Metric Samples| No       |


## [xdp-root-program]
This section is needed when bpf-chaining-enabled is set to true.

| FieldName     | Default                  | Description     | Required        |
| ------------- |--------------------------| --------------- | --------------- |
|name| `"xdp-root"`             |Name of subdirectory in which to extract artifact| Yes |
|artifact| `"l3af_xdp_root.tar.gz"` |Filename of xdp-root package. Only tar.gz and .zip formats are supported| Yes |
|ingress-map-name| `"xdp_root_array"`       |Ingress map name of xdp-root program| Yes |
|command| `"xdp_root"`             |Command to run xdp-root program| Yes |
|version| `"latest"`               |Version of xdp-root program| Yes |

## [tc-root-program]
This section is needed when bpf-chaining-enabled is set to true.

| FieldName     | Default                   | Description     | Required        |
| ------------- |---------------------------| --------------- | --------------- |
|name| `"tc-root"`               |Name of subdirectory in which to extract artifact| Yes |
|artifact| `"l3af_tc_root.tar.gz"`   |Filename of tc_root package| Yes |
|ingress-map-name| `"tc_ingress_root_array"` |Ingress map name of tc_root program| Yes |
|egress-map-name| `"tc_egress_root_array"`  |Egress map name of tc_root program,for more info about ingress/egress check [cilium](https://docs.cilium.io/en/v1.9/concepts/ebpf/intro/)| Yes |
|command| `"tc_root"`               |Command to run tc_root program| Yes |
|version| `"latest"`                |Version of tc_root program| Yes |

## [ebpf-chain-debug]
| FieldName | Default            | Description                                                    | Required |
|-----------|--------------------|----------------------------------------------------------------|----------|
| addr      | `"localhost:8899"` | Hostname and Port of chaining debug REST API                   | No       |
| enabled   | `"false"`          | Boolean to check ebpf chaining debug details is enabled or not | No       |

## [l3af-configs]
| FieldName     | Default       | Description     | Required |
| ------------- | ------------- | --------------- |----------|
|restapi-addr|`"localhost:53000"`| Hostname and Port of l3af-configs REST API | No       |

## [l3af-config-store]
| FieldName     | Default       | Description     | Required        |
| ------------- | ------------- | --------------- | --------------- |
|filename|`"/etc/l3afd/l3af-config.json"`|Absolute path of persistent config file where we are storing L3afBPFPrograms objects. For more info see [models](https://github.com/l3af-project/l3afd/blob/main/models/l3afd.go)| Yes |

## [mtls]
| FieldName     | Default                            | Description                                                                                                                                                                                                                  | Required |
| ------------- |------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|
|enabled| `"true"`                           | Boolean controlling whether mTLS is enabled or not on the REST API exposed by l3afd                                                                                                                                          | No       |
|min-tls-version| `"1.3"`                            | Minimum tls version allowed                                                                                                                                                                                                  | No       |
|cert-dir| `"/etc/l3afd/certs"`               | Absolute path of CA certificates. On Linux this points to a filesystem directory, but on Windows it can point to a [certificate store](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/certificate-stores) | No       |
|server-crt-filename| `"server.crt"`                     | Server's ca certificate filename                                                                                                                                                                                             | No       |
|server-key-filename| `"server.key"`                     | Server's mtls key filename                                                                                                                                                                                                   | No       |
|cert-expiry-warning-days| `"30"`                             | How many days before expiry you want warning                                                                                                                                                                                 | No       |
|san-match-rules| `".*l3af.l3af.io,^l3afd.l3af.io$"` | List of domain names (exact match) or regular expressions to validate client SAN DNS Names against                                                                                                                                                                  | No      |
