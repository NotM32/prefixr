# prefixr
This web service generates prefix lists from IRR entries, like those supported by Arista eOS and other vendor NOSes.

## Usage
You can run the service locally, or optionally deploy to AWS Lambda as I have.

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

## Deployment
You can deploy this service locally if desired. To build the program, simply clone this repository and run `cargo build`. 

You can also deploy this as an AWS Lambda function if desired, with the `cargo-lambda build` and `cargo-lambda deploy` commands.

The Lambda features are disabled in the default build.

## Features
Current and planned:
- [X] IPv4 and IPv6 Prefix List generation
- [X] More specific prefixes via `le` entries
- [X] Option to use own IRRd instance (latest version is required, thisp roject relies graphql for now)
- [ ] RPSL parsing for non-GraphQL IRRd instances
- [ ] Support for multiple vendor NOS (if this can be adapted for Nokia, Juniper, Cisco or other devices, please let me know)
- [ ] Support for non-http update methods

## Public Instance
A public instance of this service is made available for convenience, hosted on AWS Lambda. If demand increases, this service may move to another host. It can accessed at `pt.cubit.sh`
