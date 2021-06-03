# L3AFD
=======

L3AFD - L3 Application Foundation Daemon

L3af daemon is control plane program for Network Function (NF) as a Service.
This is an orchestration layer to manage Network Function on the host.

* Enable / Disable NF on the host
* Monitor NF programs
* Resource restrictions on NF
* Chaining of multiple NF

# Repo Status
=============

This project is currently transitioning from a closed-source project to an
open-source project. The code in this repo does not currently build due to some
lingering unavailable, closed-source dependencies.

Many of these dependencies are due to L3AFD being coupled with a custom,
proprietary control plane.

Import paths prefixed with "tbd" need to be replaced before L3AFD will build
successfully; our first priority is to replace these closed-source
dependencies:


Unavailable Dependency                 | Use Case                                 | Alternative
---------------------------------------|------------------------------------------|------------------------------------------
tbd/admind/models                      | Control plane database related objects   | Reimplement object definitions
tbd/admind-sdks/go/admindapi           | Call control plane API                   | ??
tbd/cfgdist/cdbs                       | Control plane configuration data library | Replace with generic HTTP and/or gRPC API
tbd/cfgdist/kvstores                   | Control plane configuration data library | Replace with generic HTTP and/or gRPC API
tbd/cfgdist/kvstores/cdbkv             | Control plane configuration data library | Replace with generic HTTP and/or gRPC API
tbd/cfgdist/kvstores/emitter           | Control plane configuration data library | Replace with generic HTTP and/or gRPC API
tbd/cfgdist/kvstores/versionannouncer  | Control plane configuration data library | Replace with generic HTTP and/or gRPC API
tbd/goconfig/config                    | INI Parser                               | https://github.com/robfig/config
tbd/go-shared/logs                     | Logging                                  | github.com/rs/zerolog ?
tbd/go-shared/nsqbatch                 | Control plane related messaging          | Remove
tbd/go-shared/pidfile                  | PID file creation and checking           | Reimplement or find alternative
tbd/go-shared/util                     | INI Parsing abtractions                  | Reimplement or find alternative
tbd/go-version                         | Set and print version information        | Reimplement or find alternative
tbd/net/context                        | Mirror of github.com/golang/net/context  | Use github.com/golang/net/context
tbd/sys/unix                           | Mirror of golang.org/x/sys/unix          | Use golang.org/x/sys/unix
