# DNS Client

A simple DNS client written in Java for a Computer Networks course. It builds a DNS query by hand (RFC 1034/1035), sends it over UDP to a DNS server, and parses and prints the response.

## Features

- Prompts for a hostname and sends a single Type A (IPv4) query
- Builds the DNS header and question section at the byte level (recursion desired set)
- Sends the query over UDP to Google Public DNS (`8.8.8.8`, port 53)
- Parses the response, including name compression pointers
- Prints the Question, Answer, Authority, and Additional sections

## Files

| File | Description |
|------|-------------|
| `DNSClient.java` | Main client: builds the query, sends it, parses and prints each response section |
| `NetworkDNS.java` | Alternate implementation with `nslookup`-style output (Server/Address header) |

## Requirements

- Java JDK 8 or newer
- Network access to UDP port 53

## Build and Run

```bash
javac DNSClient.java
java DNSClient
```

```
please enter a host name: www.google.com
```

The `nslookup`-style version:

```bash
javac NetworkDNS.java
java NetworkDNS
```

## Limitations

- Only Type A queries and A records are decoded; other record types are skipped
- The DNS server is hardcoded to `8.8.8.8`
- Responses are read into a 512-byte buffer (classic UDP DNS limit); no TCP fallback
- No timeout or retry handling

## References

- [RFC 1034 - Domain Names: Concepts and Facilities](https://datatracker.ietf.org/doc/html/rfc1034)
- [RFC 1035 - Domain Names: Implementation and Specification](https://datatracker.ietf.org/doc/html/rfc1035)
