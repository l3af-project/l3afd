# L3AFD: Lightweight eBPF Application Foundation Daemon

![L3AF_Logo](https://github.com/l3af-project/l3af-arch/blob/main/images/logos/Color/L3AF_logo.svg)

L3AFD is a crucial part of the L3AF ecosystem. For more information on L3AF see
https://l3af.io/

# Design

L3AFD is the primary component of the L3AF control plane. L3AFD is a daemon
that orchestrates and manages multiple eBPF programs, which we refer to as
Kernel Functions. L3AFD runs on each node where the user wishes to run Kernel
Functions. L3AFD reads configuration data and manages the execution and
monitoring of KFs running on the node.

L3AFD downloads pre-built eBPF programs from a user-configured file repository.
However, we envision the creation of a community-driven Kernel Function
Marketplace where L3AF users can obtain a variety of Kernel Functions developed
by multiple sources.

![L3AF Platform](https://github.com/l3af-project/l3af-arch/blob/main/images/L3AF_platform.png)

# Try it out

See our [L3AF Development Environment](https://github.com/l3af-project/l3af-arch/tree/main/dev_environment)
for a quick and easy way to try out L3AF on your local machine.

# Generate Swagger Docs

See our [Swaggo setup](docs/swagger.md)

# Building

To build on your local machine, do the following.

For Linux:
```
go build .
```

For Windows:
```
go build -tags WINDOWS .
```

On Linux and Windows, one can also build and generate swagger docs by doing:
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
# Contributing

Contributing to L3afd is fun. To get started:
- [Contributing guide](docs/CONTRIBUTING.md)
