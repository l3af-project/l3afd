# Guide to L3AFD Graceful Restart

## Prerequisites
To begin, ensure that you have a specific folder where the `l3afd` binary and `l3afd.cfg` files are present. By default, this should be in `/usr/local/l3afd/`.

## Directory Structure

Firstly, create a directory structure as shown below:

```
/usr/local/l3afd# tree
.
├── latest
│   ├── l3afd -> /usr/local/l3afd/v2.0.0/l3afd/l3afd
│   └── l3afd.cfg -> /usr/local/l3afd/v2.0.0/l3afd/l3afd.cfg
├── start.sh
└── v2.0.0
    └── l3afd
        ├── l3afd
        └── l3afd.cfg
```
L3afd runs a certain version (in this case, v2.0.0), and in the 'latest' folder, it is symlinked.

## Starting the l3afd Service
To start the service, run the start.sh script:

```
/usr/local/l3afd# cat start.sh
#!/bin/bash
/usr/local/l3afd/latest/l3afd --config /usr/local/l3afd/latest/l3afd.cfg &
```
Ensure that the PIDFile in the service file matches the path used in `l3afd.cfg`. This is crucial for systemd to monitor the l3afd PID.

## Upgrading to a New Version

To upgrade from v2.0.0 to v2.x.x, follow these steps. L3afd supports HTTP, HTTPS, and file protocols for downloading artifacts and tar.gz or .zip compression formats.

Here's an example of how to create an artifact:

1. Create a folder at /srv/l3afd/pkg/.
2. Inside that, create /srv/l3afd/pkg/l3afd.
3. Copy your v2.x.0 binary and cfg file to the above folder.
4. Create a tar gunzip file: `tar -czvf l3afd.tar.gz l3afd` or create a zip file.

The artifact can be served from a remote server, local server, or local folder.

For a local start, your payload for the restart would look like this:

```
{
	"hostname": "l3af-test-host",
	"version": "v2.x.x",
}
```
## Restarting the Service

To restart the service, use the following API call:

```
curl -X PUT http://localhost:7080/l3af/configs/v1/restart -d "@restart.json"
```
During this graceful restart, eBPF Programs of type probes and all user programs are restarted.

Note: During a restart, the HTTP endpoint will always be active, meaning you can make HTTP requests to that endpoint. However, all write operations (add, remove, modify program configurations) are blocked. If there are any dependent services on user_programs, you should restart them manually after restarting eBPF Programs. Expect minor metric discrepancies during the restart process.