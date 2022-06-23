# L3AFD Delete API Documentation

See [remove.json](https://github.com/l3af-project/l3af-arch/blob/main/dev_environment/cfg/remove.json) for a full example payload.

The payload will look more like this standard JSON:

```
[
  {
    "host_name" : "l3af-local-test",
    "iface" : "enp0s3",
    "want_to_remove" : {
      "xdp_ingress" : [
        {
             "ratelimiting",
             "connection-limit"
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

| FieldName     | Example       | Description     |
| ------------- | ------------- | --------------- |
| host_name | `"l3af-local-test"` | The host's name |
| iface | `"enp0s3"` | Interface name |
| want_to_remove | `""` | List of eBPF programs that we want to remove |
| xdp_ingress | `""` | Names of xdp_ingress type eBPF programs |
| tc_ingress | `""` | Names of tc_ingress type eBPF programs |
| tc_egress | `""` | Names of tc_egress type eBPF programs |