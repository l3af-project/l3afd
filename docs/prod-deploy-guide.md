# Guide to use L3AF in production environments

## Installing l3afd

Download the latest build artifacts for the last stable release on the l3afd [repo page](../../../)

## Configuring l3afd

This guide lists recommendations on how to run l3afd in a production environment.  Please see [l3afd.cfg](../config/l3afd.cfg) for a sample configuration.

The only secure configuration for production deployments at this time is with mTLS enabled.  mTLS is necessary to properly protect the REST API when running in production mode.  To securely run l3afd in a production environment please follow the configuration guidelines below.

* Make sure `environment: PROD` is set to prevent l3afd starting up in an insecure configuration.

* Ensure mTLS is set to  `enabled: true` in the configuration.

* It is recommended to use TLS version `1.3`.

* Do not use self-signed certificates.  It is always encouraged to use well-known root certificates to create server certificates and client certificates.

* The debug log API should only be enabled and set to listen on localhost when it is required to debug issues with program chaining. The debug log should normally be disabled by setting `enable: false` in the `ebpf-chain-debug` section.

* For security reasons, it is not recommended configuring l3afd to point to a public eBPF repository.  Instead, configure l3afd to point to a private mirror or local file repository once you have validated and ensured the eBPF programs are safe to run in production. 
  * eBPF repository artifacts are retrieved by joining the following elements to build the complete path: `https://<ebpf-repo-url>/<ebpf-program>/<version>/<platform>/<artifact>` or `file:///<repo-dir>/<ebpf-program>/<version>/<platform>/<artifact>`.

## Running l3afd

* l3afd on Linux needs to run with the `CAP_SYS_ADMIN` or with the `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_PERFMON` privileges (newer kernels). Unprivileged users will not have the necessary permissions to load eBPF programs.

* l3afd only supports handling the following signals `SIGINT`, `SIGTERM`, which will cause l3afd to perform a clean shut down.

* l3afd can be configured through a system manager to start on boot, such as systemd.
