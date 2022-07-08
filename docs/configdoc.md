# L3AFD Config Options Documentation

See [l3afd.cfg](https://github.com/l3af-project/l3af-arch/blob/main/dev_environment/cfg/l3afd.cfg) for a full example configuration.


```
[DEFAULT]

[l3afd]
pid-file: ./l3afd.pid
datacenter: dummy
bpf-dir: /dev/shm
bpf-log-dir:
kernel-major-version: 4
kernel-minor-version: 15
shutdown-timeout: 1s
http-client-timeout: 10s
max-nf-restart-count: 3
bpf-chaining-enabled: true
swagger-api-enabled: false
# PROD | DEV
environment: PROD
....
```

### Below is the detailed documentation for each field


## [l3afd]
| FieldName     | Example       | Description     | Required        |
| ------------- | ------------- | --------------- | --------------- |
|pid-file| `"./l3afd.pid"`  | The path to the l3afd.pid file which contains process id of L3afd | Yes |
|datacenter| `"dummy"` | Name of Datacenter| Yes |
|bpf-dir| `"/dev/shm"` | Absolute Path where eBPF packages are to be extracted | Yes |
|bpf-log-dir|`""`      | Absolute Path for log files, which is passed to applications on the command line. L3afd does not store any logs itself.| No |
|kernel-major-version|`"4"`|Major version of the kernel| Only on linux |
|kernel-minor-version|`"15"`|Minor version of the kernel (Ex 4.15)| Only on linux |
|shutdown-timeout|`"1s"`|Maximum amount of time allowed for l3afd to gracefully stop. After shutdown-timeout, l3afd will exit even if it could not stop applications.| No |
|http-client-timeout|`"10s"`|Maximum amount of time allowed to get HTTP response headers when fetching a package from a repository| No |
|max-nf-restart-count|`"3"`|Maximum number of tries to restart eBPF applications if they are not running| No |
|bpf-chaining-enabled|`"true"`|Boolean to set bpf-chaining. For more info about bpf chaining check [L3AF_KFaaS.pdf](https://github.com/l3af-project/l3af-arch/blob/main/L3AF_KFaaS.pdf)| Yes |
|swagger-api-enabled|`"false"`|Whether the swagger API is enabled or not.  For more info see [swagger.md](https://github.com/l3af-project/l3afd/blob/main/docs/swagger.md)| No |
|environment|`"PROD"`|If set to anything other than "PROD", mTLS security will not be checked| Yes |
|BpfMapDefaultPath|`"/sys/fs/bpf"`|The base pin path for eBPF maps| Yes |

## [kf-repo]
| FieldName     | Example       | Description     | Required        |
| ------------- | ------------- | --------------- | --------------- |
|url| `"http://localhost:8000/"`|Default repository from which to download eBPF packages| No |

## [web]
| FieldName     | Example       | Description     |  Required        |
| ------------- | ------------- | --------------- |  --------------- |
|metrics-addr|`"0.0.0.0:8898"`|Prometheus endpoint for pulling/scraping the metrics.  For more info about Prometheus see [prometheus.io](https://prometheus.io/) | Yes |
|kf-poll-interval|`"30s"`|Periodic interval at which to scrape metrics using Prometheus| Yes |
|n-metric-samples|`"20"`|Number of Metric Samples| Yes |


## [xdp-root-program]
| FieldName     | Example       | Description     | Required        |
| ------------- | ------------- | --------------- | --------------- |
|name|`"xdp-root"`|Name of subdirectory in which to extract artifact| Yes |
|artifact|`"xdp-root.tar.gz"`|Filename of xdp-root package. Only tar.gz and .zip formats are supported| Yes |
|ingress-map-name|`"root_array"`|Ingress map name of xdp-root program| Yes |
|command|`"xdp_root"`|Command to run xdp-root program| Yes |
|version|`"1.01"`|Version of xdp-root program| Yes |
|user-program-daemon|`"false"`|Set to true it requires l3afd to stop the application (via SIGTERM on Linux or SIGKILL on Windows)| Yes |

## [tc-root-program]
| FieldName     | Example       | Description     | Required        |
| ------------- | ------------- | --------------- | --------------- |
|name|`"tc_root"`|Name of subdirectory in which to extract artifact| Yes |
|artifact|`"l3af_tc_root.tar.gz"`|Filename of tc_root package| Yes |
|ingress-map-name|`"tc_ingress_root_array"`|Ingress map name of tc_root program| Yes |
|egress-map-name|`"tc_egress_root_array"`|Egress map name of tc_root program,for more info about ingress/egress check [cilium](https://docs.cilium.io/en/v1.9/concepts/ebpf/intro/)| Yes |
|command|`"tc_root"`|Command to run tc_root program| Yes |
|version|`"1.0"`|Version of tc_root program| Yes |
|user-program-daemon|`"false"`|Boolean to check xdp-root is user-program daemon or not| Yes |

## [l3af-configs]
| FieldName     | Example       | Description     | Required        |
| ------------- | ------------- | --------------- | --------------- |
|restapi-addr|`"localhost:53000"`| Hostname and Port of l3af-configs REST API | Yes |

# [l3af-config-store]
| FieldName     | Example       | Description     | Required        |
| ------------- | ------------- | --------------- | --------------- |
|filename|`"/etc/l3afd/l3af-config.json"`|Absolute path of persistent config file where we are storing L3afBPFPrograms objects. For more info see [models](https://github.com/l3af-project/l3afd/blob/main/models/l3afd.go)| Yes |

# [mtls]
| FieldName     | Example       | Description     | Required        |
| ------------- | ------------- | --------------- | --------------- |
|enabled| `"true"` | Boolean to check mtls enabled or not on REST API exposed by l3afd| Yes |
|min-tls-version|`"1.3"`| Minimum tls version allowed| No |
|cert-dir|`"/etc/l3af/certs"`|Absolute path of ca certificates. In Linux Context it is pointing to a filesystem directory, but in Windows it can point to [certificate store](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/certificate-stores) | Yes |
|server-crt-filename|`"server.crt"`|Server's ca certificate filename| Yes |
|server-key-filename|`"server.key"`|Server's mtls key filename| Yes |
|cert-expiry-warning-days|`"30"`|How many days before expiry you want warning| No |