# L3AFD: Lightweight eBPF Daemon
![L3AF_Logo](https://github.com/l3af-project/l3af-arch/blob/main/images/logos/Color/L3AF_logo.svg)

[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/6075/badge)](https://bestpractices.coreinfrastructure.org/projects/6075)

L3AFD is a crucial part of the L3AF ecosystem. For more information on L3AF see
https://l3af.io/

# Overview
L3AFD is the primary component of the L3AF control plane. L3AFD is a daemon
that orchestrates and manages multiple eBPF programs. L3AFD runs on each node
where the user wishes to run eBPF programs. L3AFD reads configuration data and
manages the execution and monitoring of eBPF programs running on the node.

L3AFD downloads pre-built eBPF programs from a user-configured repository.
However, we envision the creation of a community-driven eBPF package marketplace
where L3AF users can obtain a variety of eBPF programs developed by multiple
sources.

![L3AF Platform](https://github.com/l3af-project/l3af-arch/blob/main/images/L3AF_platform.png)

# Try it out
See our [L3AF Development Environment](https://github.com/l3af-project/l3af-arch/tree/main/dev_environment)
for a quick and easy way to try out L3AF on your local machine.

# Installing
Try [a binary release](https://github.com/l3af-project/l3afd/releases/latest).

# Building
To build on your local machine, including swagger docs do the following.

For Linux:
```
make
```

For Windows:
```
cmake -B build
cmake --build build
```

# Testing
To test on your local machine, do the following.

For Linux:
```
go test ./...
```

For Windows:
```
go test -tags WINDOWS ./...
```

# Generate Swagger Docs
See our [Swaggo setup](docs/swagger.md)

# Contributing
Contributing to L3afd is fun. To get started:
- [Contributing guide](docs/CONTRIBUTING.md)
