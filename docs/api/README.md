# L3AFD API Documentation

Please note that the L3AFD API is unstable and a work in progress.

See [payload.json](https://github.com/l3af-project/l3af-arch/blob/main/dev_environment/cfg/payload.json) for a full example payload.

Below is the detailed documentation for each field:

|Key|Type|Example|Description|
|--- |--- |--- |--- |
|key|string|`"bpfdev-sc5"`|Name of host running L3AFD|
|value|string of [value](#value) object|See [value example](#value-example)|Which eBPF programs to run and how to run them|

NOTICE: The structure of the API payload is due to historical reasons. Soon,
we will be restructuring the payload such that the string values are unpacked
to valid JSON objects. For example, instead of:

``json
{
"key": "l3af-local-test",
"value":"{\"bpf_programs\":{\"enp0s3\":{\"xdpingress\":{\"1\":{\"name\":\"ratelimiting\",\"seq_id\":1,\"artifact\":\"l3af_ratelimiting.tar.gz\",\"map_name\":\"/sys/fs/bpf/xdp_rl_ingress_next_prog\",\"cmd_start\":\"ratelimiting\",\"version\":\"latest\",\"is_user_program\":true,\"admin_status\":\"enabled\",\"ebpf_type\":\"xdp\",\"cfg_version\":1,\"start_args\":[{\"key\":\"ports\",\"value\":\"8080,8081\"},{\"key\":\"rate\",\"value\":\"2\"}],\"monitor_maps\":[{\"name\":\"rl_drop_count_map\",\"key\":0,\"aggregator\":\"scalar\"},{\"name\":\"rl_recv_count_map\",\"key\":0,\"aggregator\":\"max-rate\"}]}}}}}"
}
``

The payload will look more like this standard JSON:

```json
{
  "hostname": "l3af-local-test",
  "bpf_programs": {
    "enp0s3": {
      "xdpingress": [
        {
          "name": "ratelimiting",
          "artifact": "l3af_ratelimiting.tar.gz",
          "map_name": "/sys/fs/bpf/xdp_rl_ingress_next_prog",
          "...": "..."
        }
      ],
      "monitor_maps": [
        {
          "...": "..."
        }
      ]
    }
  }
}
```

## value

|Key|Type|Example|Description|
|--- |--- |--- |--- |
|name|string|ratelimiting|Name of the eBPF Program|
|seq_id|number|`1`|Position of the eBPF program in the chain, 1 represents the first program in the chain|
|artifact|string|`"l3af_ratelimiting.tar.gz"`|User code binary and eBPF byte code in tar.gz format.|
|map_name|string|`"/sys/fs/bpf/ep1_next_prog_array"`|Chaining program map in the file system with path|
|cmd_start|string|`"ratelimiting"`|User program name to start the eBPF program|
|cmd_stop|string||User program name to stop the eBPF program|
|cmd_status|string||User program name to status the eBPF program|
|version|string|`"latest"`|The version of the eBPF Program|
|is_user_program|boolean|`true` or `false`|The true means the user program is running beyond the eBPF attach/link, false means the user program stops after the eBPF program is attached.|
|admin_status|string|`"enabled"` or `"disabled"`|This represents the program status. `"enabled"` means to be started if not running.  "disabled"` means to be stopped if running|
|ebpf_type|string|`"XDP"` or `"TC"`|Type of eBPF program. Currently only XDP and TC network programs are supported.|
|cfg_version|number|`1`|Payload version number|
|start_args|array of [start_args](#start_args) objects|`[{"key" : "collector_ip", "value":"10.10.10.2"}`]|Argument list passed while starting the KF|
|stop_args|array of [stop_args](#stop_args) objects||Argument list passed while stopping the KF|
|status_args|array of [status_args](#status_args) objects||Argument list passed while checking the running status of the KF|
|map_args|array of [map_args](#map_args) objects||eBPF map to be updated with the value passed in the config|
|monitor_maps|array of [monitor_maps](#monitor_maps) objects|`[{"name":"cl_drop_count_map","key":0,"aggregator":"scalar"}]`|List of eBPF map names, index and aggregator function(i.e. scalar,max-rate)|

Note: `name`, `version`, the Linux distribution name, and `artifact` are
combined with the configured KF repo URL into the path that is used to download
the artifact containing the eBPF program. For example, if
`name="ratelimiting"`, `version="latest"`, and
`artifact="l3af_ratelimiting.tar.gz"` and L3AFD is running on Ubuntu 20.04.3
LTS (Focal Fossa), then we would look for the artifact at:

`http://{kf repo configured in l3afd.cfg}/ratelimiting/latest/focal/l3af_ratelimiting.tar.gz`

### value example

`"{\"bpf_programs\":{\"enp0s3\":{\"xdpingress\":{\"1\":{\"name\":\"ratelimiting\",\"seq_id\":1,\"artifact\":\"l3af_ratelimiting.tar.gz\",\"map_name\":\"/sys/fs/bpf/xdp_rl_ingress_next_prog\",\"cmd_start\":\"ratelimiting\",\"version\":\"latest\",\"is_user_program\":true,\"admin_status\":\"enabled\",\"ebpf_type\":\"xdp\",\"cfg_version\":1,\"start_args\":[{\"key\":\"ports\",\"value\":\"8080,8081\"},{\"key\":\"rate\",\"value\":\"2\"}],\"monitor_maps\":[{\"name\":\"rl_drop_count_map\",\"key\":0,\"aggregator\":\"scalar\"},{\"name\":\"rl_recv_count_map\",\"key\":0,\"aggregator\":\"max-rate\"}]},\"2\":{\"name\":\"connection-limit\",\"seq_id\":2,\"artifact\":\"l3af_connection_limit.tar.gz\",\"map_name\":\"/sys/fs/bpf/xdp_cl_ingress_next_prog\",\"cmd_start\":\"connection_limit\",\"version\":\"latest\",\"is_user_program\":true,\"is_plugin\":false,\"admin_status\":\"enabled\",\"ebpf_type\":\"xdp\",\"cfg_version\":1,\"start_args\":[{\"key\":\"max-conn\",\"value\":\"5\"},{\"key\":\"ports\",\"value\":\"8080,8081\"}],\"monitor_maps\":[{\"name\":\"cl_conn_count\",\"key\":0,\"aggregator\":\"scalar\"},{\"name\":\"cl_drop_count_map\",\"key\":0,\"aggregator\":\"scalar\"},{\"name\":\"cl_recv_count_map\",\"key\":0,\"aggregator\":\"scalar\"}]}}}}}"`

## start_args

|Key|Type|Example|Description|
|--- |--- |--- |--- |
|key|string|`"ports"`|A command-line argument to use when starting the KF userspace program|
|value|string|`"8080,8081"`|A corresponding command-line argument value to use when starting the KF userspace program|

## stop_args

|Key|Type|Example|Description|
|--- |--- |--- |--- |
|key|string|`"ports"`|A command-line argument to use when running cmd_stop|
|value|string|`"8080,8081"`|A corresponding command-line argument value to use when running cmd_stop|


## status_args

|Key|Type|Example|Description|
|--- |--- |--- |--- |
|key|string|`"ports"`|A command-line argument to use when running cmd_status|
|value|string|`"8080,8081"`|A corresponding command-line argument value to use when running cmd_status|

## map_args

|Key|Type|Example|Description|
|--- |--- |--- |--- |
|key|string||Name of the map in which to write `value`|
|value|string||The value to write into the eBPF map named specified by `key`|

## monitor_maps

|Key|Type|Example|Description|
|--- |--- |--- |--- |
|name|string|`"rl_drop_count_map"`|The name of the map where metrics are stored|
|key|number|0|The index in the map specified by `name` where metrics are stored|
|aggregator|string|scalar|The type of metrics aggregation to use for the configured metric sampling interval. Supported values are `"scalar"`, `"max-rate"`, and `"avg"`.|
