# prefixr
[![Rust](https://github.com/NotM32/prefixr/actions/workflows/rust.yml/badge.svg?event=push)](https://github.com/NotM32/prefixr/actions/workflows/rust.yml)

A web service that generates prefix-list and as-path ACLs for Arista/Cisco networking devices, from Internet Routing Registry entries.

## Usage
You can run the service locally, or optionally deploy to AWS Lambda.

Some vendor NOS support updating a prefix-list via source URL. On Arista eOS you can use this style of configuration:

```
ip prefix-list AS33063:AS-CONE source https://your-url.com/ipv4/prefix-list/AS33063:AS-CONE/24
```

This should recursively fetch all prefixes that the `AS-CONE` covers. `route-set`, `aut-num`, and `as-set` entries are supported. The functionality is similar to `bgpq4`.

The `/24` at the end of the URL is optionally provided. If provided, route entries will be generate with a `le` definition equal to the provided minimum accepted length. For instance:

```
seq 10 permit 10.0.0.0/8 le 24
seq 20 permit 192.168.0.0/24
```

The IRRd server is configurable. Your IRRd server must be a new enough version to provide GraphQL. Public IRRd servers may or may not provide a GraphQL endpoint; NTT's `rr.ntt.net` supports this, however RADb does not have a production GraphQL endpoint that I am aware of.

### Examples

**Prefix List**
Create a list of entries in `ip prefix-list` format.
```http
GET /prefix-list/{irr_object}                 # Generates an IPv4 prefix list from irr_object
GET /{ipv4 | ipv6}/{irr_object}               # Generates an IPv4 or IPv6 prefix list irr_object
GET /prefix-list/{irr_object}/{min_length}    # Generates an IPv4 prefix list from irr_object with le value equal to min_length
```

The Arista/Cisco format entry list is compatible with the `ip prefix-list {name} source` configuration stanza present in eOS. You can also use a script to query and build a configuration template.

Supports `AutNum`, `AsSet`, or `RouteSet` IRR objects.

Prefixes are recursively resolved from the IRR object.

**AS-Path ACL**
Create an AS-Path list from an IRR AS-Set object.

``` http
GET /as-path-acl/{irr_object}
```

Compatible with the `ip as-path access-list {name} source` command. 

The output of this can be very verbose, as all ASNs are recursively resolved.

## Deployment
You can deploy this service locally if desired. To build the program, simply clone this repository and run `cargo build`. 

You can also deploy this as an AWS Lambda function if desired, with the `cargo-lambda build` and `cargo-lambda deploy` commands.

The Lambda features are disabled in the default build.

## Features
Current and planned:
- [X] IPv4 and IPv6 Prefix List generation
- [X] More specific prefixes via `le` entries
- [X] Option to use own IRRd instance (latest version is required, thisp roject relies graphql for now)
- [X] RPSL parsing for non-GraphQL IRRd instances
- [ ] Support for multiple vendor NOS (if this can be adapted for Nokia, Juniper, Cisco or other devices, please let me know)
- [ ] Support for non-http update methods

## Public Instance
A public instance of this service is made available for convenience, hosted on AWS Lambda. If demand increases, this service may move to another host. It can accessed at `pt.cubit.sh`
