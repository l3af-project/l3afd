# L3AFD: Lightweight eBPF Application Foundation Daemon

![L3AF_Logo](https://raw.githubusercontent.com/l3af-project/l3af-arch/54e95037f1a51b924ec2ce0eee3d3bb27f488878/images/logos/Color/L3AF_logo.svg?token=AABDYXUSFCV66FZRJ6IFMLDBL7AZ6&raw=true)

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

![L3AF Platform](https://raw.githubusercontent.com/l3af-project/l3af-arch/main/images/L3AF_platform.png?token=AABDYXU5OXHBOC2E4PEPUKLBL7BEW&raw=true)

# Try it out

TODO
