# L3AFD API Documentation

# Update API

See [payload.json](https://github.com/l3af-project/l3af-arch/blob/main/dev_environment/cfg/payload.json) for a full example payload.

The payload will look more like this standard JSON:

```
[
  {
    "host_name" : "l3af-local-test",
    "iface" : "enp0s3",
    "bpf_programs" : {
      "xdp_ingress" : [
        {
          "name": "ratelimiting",
          "seq_id": 1,
          "artifact": "l3af_ratelimiting.tar.gz",
          "ebpf_package_repo_url": "https://l3af.io"
          "map_name": "xdp_rl_ingress_next_prog",
          "cmd_start": "",
          "version": "latest",
          "user_program_daemon": true,
          "admin_status": "enabled",
          "prog_type": "xdp",
          "cfg_version": 1,
          "map_args": { "rl_ports_map": "8080,8081", "rl_config_map": "2" },
          "monitor_maps": [
            { "name": "rl_drop_count_map", "key": 0, "aggregator": "scalar"},
            { "name": "rl_recv_count_map", "key": 0, "aggregator": "max-rate"}
          ],
          "object_file": "ratelimiting_kern.o",
          "entry_function_name": "_xdp_ratelimiting"
        }
        ],
      "tc_ingress":[
        {"...": "..."}
        ],
      "tc_egress": [
        {"...":  "..."}
      ]
    }
  }
]
```

### Below is the detailed documentation for each field

| Key                   | Type                                           | Example                                                        | Description                                                                                                                                                                                                                                                                                                          |
|-----------------------|------------------------------------------------|----------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| name                  | string                                         | ratelimiting                                                   | Name of the BPF Program                                                                                                                                                                                                                                                                                              |
| seq_id                | number                                         | `1`                                                            | Position of the BPF program in the chain. Count starts at 1.                                                                                                                                                                                                                                                         |
| artifact              | string                                         | `"l3af_ratelimiting.tar.gz"`                                   | Userspace BPF program binary and kernel BPF program byte code in tar.gz format                                                                                                                                                                                                                                       |
| ebpf_package_repo_url | string                                         | `"https://l3af.io/"`                                           | eBPF package repository URL.  If it is not provided default URL is used.                                                                                                                                                                                                                                             |
| map_name              | string                                         | `"ep1_next_prog_array"`                                        | Chaining program map to pin to. This should match the BPF program code.                                                                                                                                                                                                                                              |
| cmd_start             | string                                         | `"ratelimiting"`                                               | The command used to start the userspace program. Usually the userspace program binary name. This userspace program can load bpf program (i.e. not loaded by l3afd) and execute custom logic. If the BPF program is loaded by userspace program then initial linking of BPF program should be handled by this program. |
| cmd_stop              | string                                         |                                                                | The command used stop the userspace program. This program should unlink the program and cleanup the BPF maps                                                                                                                                                                                                         |
| cmd_status            | string                                         |                                                                | The command used to get the status of the BPF program.                                                                                                                                                                                                                                                               |
| cmd_update            | string                                         |                                                                | The command used to start the program to update BPF maps dynamically. Usually the userspace program binary name.                                                                                                                                                                                                     |
| version               | string                                         | `"latest"`                                                     | The version of the BPF Program                                                                                                                                                                                                                                                                                       |
| user_program_daemon   | boolean                                        | `true` or `false`                                              | Whether the userspace program continues running after the BPF program is started                                                                                                                                                                                                                                     |
| admin_status          | string                                         | `"enabled"` or `"disabled"`                                    | This represents the program status. `"enabled"` means to be started if not running.  `"disabled"` means to be stopped if running                                                                                                                                                                                     |
| prog_type             | string                                         | `"xdp"` or `"tc"`                                              | Type of BPF program. Currently only XDP and TC network programs are supported.                                                                                                                                                                                                                                       |
| cfg_version           | number                                         | `1`                                                            | Payload version number                                                                                                                                                                                                                                                                                               |
| start_args            | map                                            | `{"collector_ip": "10.10.10.2", "verbose":"2"}`                | Argument list passed while starting the userspace program using cmd_start.                                                                                                                                                                                                                                           |
| stop_args             | map                                            |                                                                | Argument list passed while stopping the userspace program using cmd_stop.                                                                                                                                                                                                                                            |
| status_args           | map                                            |                                                                | Argument list passed while checking the running status of the user program using cmd_status.                                                                                                                                                                                                                         |
| map_args              | map                                            | `{"rl_config_map": "2", "rl_ports_map":"80,443"}`              | BPF map to be updated with the value provided in the config. This option can only be utilized when object file provided to load by l3afd.                                                                                                                                                                            |
| update_args           | map                                            |                                                                | Argument list passed while calling cmd_update to update the configuration BPF maps.  A program must have logic to parse the map argument and update the appropriate configuration maps for the BPF program.                                                                                                  |
| monitor_maps          | array of [monitor_maps](#monitor_maps) objects | `[{"name":"cl_drop_count_map","key":0,"aggregator":"scalar"}]` | The BPF maps to monitor for metrics and how to aggregate metrics information at each interval metrics are sampled. This option can only be utilized when object file provided to load by l3afd.                                                                                                                      |
| object_file           | string                                         | `ratelimiting_kern.o`                                          | The Object file containing BPF programs and maps, this option is needed to load BPF program from l3afd                                                                                                                                                                                                               |
| entry_function_name   | string                                         | `_xdp_ratelimiting`                                            | The BPF program entry function name, this option is needed to load BPF program from l3afd                                                                                                                                                                                                                            |

Note: `name`, `version`, the Linux distribution name, and `artifact` are
combined with the configured ebpf-repo URL into the path that is used to download
the artifact containing the BPF program. For example, if
`name="ratelimiting"`, `version="latest"`, and
`artifact="l3af_ratelimiting.tar.gz"` and L3AFD is running on Ubuntu 20.04.3
LTS (Focal Fossa), then we would look for the artifact at:

`http://{ebpf-repo configured in l3afd.cfg}/ratelimiting/latest/focal/l3af_ratelimiting.tar.gz`

## monitor_maps

|Key|Type|Example|Description|
|--- |--- |--- |--- |
|name|string|`"rl_drop_count_map"`|The name of the map where metrics are stored|
|key|number|0|The index in the map specified by `name` where metrics are stored|
|aggregator|string|scalar|The type of metrics aggregation to use for the configured metric sampling interval. Supported values are `"scalar"`, `"max-rate"`, and `"avg"`.|




# Add API 
The JSON is the same as for the Update API. Refer to above documentation.


# Delete API 

See [delete_payload.json](https://github.com/l3af-project/l3af-arch/blob/main/dev_environment/cfg/delete_payload.json) for a full example payload.

The payload will look more like this standard JSON:

```
[
    {
        "host_name": "l3af-local-test",
        "iface": "fakeif0",
        "bpf_programs": {
            "xdp_ingress": [
                "ratelimiting",
                "connection-limit"
            ],
            "tc_ingress": [
              "...",
              "..."
            ],
            "tc_egress": [
              "...", 
              "..."
            ]
        }
    }
]

```

### Below is the detailed documentation for each field

| FieldName     | Example       | Description                           |
| ------------- | ------------- |---------------------------------------|
| host_name | `"l3af-local-test"` | The host's name                       |
| iface | `"fakeif0"` | Interface name                        |
| bpf_programs | `""` | List of BPF program names             |
| xdp_ingress | `""` | Names of xdp ingress type BPF programs |
| tc_ingress | `""` | Names of tc ingress type BPF programs |
| tc_egress | `""` | Names of tc egress type BPF programs  |

