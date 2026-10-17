# Computer Networks — Multi-Service Network Security & Protocol Suite

[![Course](https://img.shields.io/badge/Course-Computer%20Networks%202025--2026-blue.svg)](https://fmi.unibuc.ro/)
[![Faculty](https://img.shields.io/badge/Faculty-FMI%20UniBuc-blue.svg)](https://fmi.unibuc.ro/)
[![Docker Compose](https://img.shields.io/badge/Docker%20Compose-v2+-0db7ed.svg?logo=docker)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3.12-3776ab.svg?logo=python)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Completed-success.svg)](#)

A comprehensive suite of network services, protocol implementations, analytical tools, and penetration testing demonstrations developed for the **Computer Networks (Rețele de Calculatoare)** course at the **Faculty of Mathematics and Computer Science, University of Bucharest**.

The repository brings together custom DNS systems (an iterative recursive DNS resolver with ad-blocking and DNS-over-HTTPS), covert network channel engineering (DNS tunneling with reliable transfer and chunk-level resume), nationwide email infrastructure analysis (MXMap for Romanian municipalities), and active network attack simulations (ARP cache poisoning and stateful TCP session hijacking).

---

## 👥 The Team & Contributions

This project was built collaboratively by **The Admins** team. Responsibilities were divided as follows:

* **Andrei ([@andrei12225](https://github.com/andrei12225))**
  * **Server & VPS Orchestration**: Configured VPS infrastructure, reverse proxies, and production deployment across domains under `*.andrei12225.engineer`.
  * **ARP Spoofing (`arp_spoofing/`)**: Developed automated bidirectional ARP cache poisoning using Scapy layer-2 frames and network restoration utilities.
  * **TCP Session Hijacking (`tcp_hijacking/`)**: Implemented Linux `iptables` NFQUEUE packet interception, HTTP compression and version downgrade, stateful TCP sequence & acknowledgment number tracking across sessions, automated payload alteration (swapping the UniBuc header image with a hyrax image), and containerized Firefox testing environment.
  * **Ad Statistics Service (`ad_stats/`) & Central Dashboard (`home_website/`)**: Created the Flask-based real-time telemetry dashboard for blocked domains with company-level categorization, thread-safe persistence, and the Node.js/Express landing page.

* **Robert ([@AngRobert](https://github.com/AngRobert))**
  * **MXMap (`mxmap/`)**: Formulated SPARQL queries to query Wikidata for all Romanian Administrative Territorial Units (UATs) and their official emails. Engineered a Scapy-based DNS inspection pipeline querying MX records, parsing SPF TXT records, resolving mail server IPs, querying the ipinfo.io API, classifying mail servers into local/hybrid/foreign categories, merging polygon geometries into GeoJSON, and developing the Leaflet.js interactive dark-mode web application.
  * **DNS Tunneling (`dnstunnel/`)**: Designed and implemented custom covert channel communication over DNS TXT records. Built the custom authoritative UDP DNS server with Base64 chunking, the resilient client featuring stop-and-wait retransmissions, timeout management, resumable file transfer (handling truncated chunks), and MD5 checksum validation, along with a Flask web UI supporting live Server-Sent Events (SSE) progress streaming.

* **Toma ([@Meanderingg](https://github.com/Meanderingg))**
  * **DNS AdBlocker (`AdBlockerDns/`)**: Implemented a dual-stack (IPv4 & IPv6 `::`) UDP DNS server on port 53. Built the domain filtering engine matching curated ad/tracker blacklists and responding with sinkhole IPs (`0.0.0.0` and `0:0:0:0:0:0:0:0`) with asynchronous reporting to `ad_stats`.
  * **Iterative & Recursive Resolver (`recursive_resolver.py`)**: Built a full DNS resolver from scratch that traverses the DNS hierarchy starting from root nameservers down to authoritative nameservers, supporting A, AAAA, CNAME resolution chains, MX, and SOA records with loop prevention and FIFO caching.
  * **DNS over HTTPS Gateway (`DohEndpoint/`)**: Built an RFC 8484-compliant DoH gateway using FastAPI that decodes Base64URL GET and binary POST DNS queries, forwards them to the internal UDP DNS service, and returns `application/dns-message` responses.

---

## 🏛️ System Architecture

The entire project is containerized into a multi-network Docker Compose setup comprising 8 distinct microservices communicating over three isolated subnets (`subnet1`: `172.10.0.0/16`, `subnet2`: `198.10.0.0/16`, and `subnet_Dns`: `67.67.0.0/16`).

### Network Topology & Services

| Service Name | Container / Path | Network & IP | Exposed Host Port | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **`dashboard`** | `./home_website/` | `subnet1`: `172.10.0.10` | `3000:3000` | Central project showcase portal (Express.js) |
| **`mxmap`** | `./mxmap/` | `subnet1`: `172.10.0.20` | `5000:5000` | Romanian municipality email infrastructure map (Flask + Leaflet) |
| **`dnstunnel_server`** | `./dnstunnel/server/` | `subnet1`: `172.10.0.30` | `5002:5002/udp` | Authoritative DNS server for file transfers |
| **`dnstunnel_flask`** | `./dnstunnel/flask/` | `subnet1`: `172.10.0.40` | `5001:5001` | DNS tunnel client with SSE live transfer streaming |
| **`ad_stats`** | `./ad_stats/` | `subnet1`: `172.10.0.50`<br>`subnet_Dns`: `67.67.0.12` | `5050:5050` | Telemetry aggregator and company classification engine |
| **`dns_adblocker_udp`**| `./AdBlockerDns/` | `subnet_Dns`: `67.67.0.10`| `53:53/udp` | Ad-blocking DNS resolver with iterative resolution |
| **`doh_endpoint`** | `./AdBlockerDns/DohEndpoint/` | `subnet_Dns`: `67.67.0.11` | `8000:5001` | RFC 8484 DNS-over-HTTPS (DoH) endpoint |
| **`server`** | `./tcp_hijacking/server/` | `subnet2`: `198.10.0.2` | `5800:5800`, `5900:5900` | Target Firefox browser in Docker via web VNC |
| **`middle`** | `./tcp_hijacking/` | `subnet2`: `198.10.0.3` | *Internal* | Attacker container running ARP poisoning and NFQUEUE hijacking |
| **`router`** | `./tcp_hijacking/` | `subnet1`: `172.10.0.1`<br>`subnet2`: `198.10.0.1` | *Internal* | Inter-subnet gateway router with IP forwarding |
| **`client`** | `./tcp_hijacking/` | `subnet1`: `172.10.0.2` | *Internal* | Client container for end-to-end routing tests |

---

## 🔍 Modules in Detail

### 1. DNS AdBlocker, Recursive Resolver & DoH (`AdBlockerDns/` & `ad_stats/`)

A Pi-hole inspired network-level ad and tracker blocker that also implements an iterative recursive DNS resolver and a DoH proxy.

* **UDP DNS Server (`udp_dns_server.py`)**:
  * Listens on dual-stack IPv6/IPv4 (`::` on UDP port 53).
  * Loads over 60,000 known ad, tracking, and malware domains from `adresses.txt` and `facebook.txt`.
  * **Sinkholing**: If a requested domain matches the blacklist, it returns `0.0.0.0` (for type `A`) or `0:0:0:0:0:0:0:0` (for type `AAAA`) with a custom TTL.
  * **Asynchronous Telemetry**: Sends a non-blocking HTTP POST notification to `http://67.67.0.12:5050/block` on every blocked request.
  * **In-Memory Caching**: Implements a FIFO cache for fast response times on repeated queries.
* **Recursive Resolver (`recursive_resolver.py`)**:
  * Does not forward queries to third-party public resolvers (like `8.8.8.8`). Instead, it performs true iterative DNS resolution starting from root server `198.41.0.4` (`a.root-servers.net`).
  * Follows Name Server (`NS`) referrals down the hierarchy, querying authoritative nameservers until obtaining the final answer.
  * Handles record types: `A` (IPv4), `AAAA` (IPv6), `CNAME` (canonical name alias chasing), `MX` (mail exchanger), and `SOA` (start of authority).
  * Includes loop detection (`visitedIp` set) and recursion depth limits to prevent resolution storms.
* **DNS-over-HTTPS Endpoint (`DohEndpoint/doh_decoder.py`)**:
  * FastAPI application exposing an RFC 8484 compliant `/dns_adblocker` endpoint.
  * Supports both **GET** queries with Base64URL-encoded DNS payloads (`?dns=...`) and **POST** queries with raw binary `application/dns-message` content.
  * Forwards the parsed query to `dns_adblocker_udp:53` and relays back binary DNS replies.
* **Ad Statistics Service (`ad_stats/app.py`)**:
  * Aggregates telemetry of blocked queries in thread-safe storage (`threading.Lock` writing to `data/stats.json`).
  * Classifies domains by company based on keyword heuristics (Google, Meta/Facebook, Microsoft, Amazon, TikTok/ByteDance, Apple, Twitter/X, Spotify, Netflix, AdColony, Taboola, Outbrain, etc.).
  * Provides a real-time web UI showing total blocked queries, company distribution charts, and a rolling log of the last 100 blocked domains.

---

### 2. MXMap — Romanian Municipality Mail Infrastructure (`mxmap/`)

An analytical geospatial project exploring email sovereignty across Romania's local public administration (cities, communes, municipalities, and Bucharest sectors).

```
   [Wikidata SPARQL Query]
             │
             ▼
   [Extract Official Emails]
             │
             ▼
   [Scapy DNS Resolution]
      ├── MX Records (mail exchanger + priority)
      ├── TXT Records (SPF validation: v=spf1)
      └── A Records (IP of lowest preference MX)
             │
             ▼
   [ipinfo.io Geolocation & ASN Lookup]
             │
             ▼
   [Classification Engine]
      ├── Local: Romanian IP & clean SPF (no foreign relays)
      ├── Hybrid: Romanian IP but contains foreign SPF inclusions
      └── Foreign: Mail hosted outside Romania
             │
             ▼
   [GeoJSON Fusion & Interactive Leaflet Dashboard]
```

* **Data Harvesting (`wikidata_query.txt`)**:
  * Uses a SPARQL query targeting Wikidata items belonging to Romania (`P17=Q218`) categorized as Romanian municipalities (`wd:Q640364`), Bucharest sectors (`wd:Q15921300`), or subclasses of Romanian UATs (`wd:Q697379`), extracting their official email addresses (`P968`) and counties (`P131`).
* **DNS Inspection Engine (`get_info.py`)**:
  * Extracts domain components and sends low-level Scapy DNS packets:
    * `MX` query: Parses exchange records and selects the server with the lowest preference number (highest priority).
    * `TXT` query: Parses SPF strings (`v=spf1 ...`) looking for foreign relay inclusions (`FOREIGN_SPF` list covering Google Workspace, Microsoft 365, Amazon SES, SendGrid, Zoho, Mailchimp, Brevo, etc.).
    * `A` query: Resolves the IP address of the chosen MX host.
  * Calls the `ipinfo.io` API to retrieve country of origin and Autonomous System name.
  * Categorizes each institution:
    * **`local`**: Romanian hosting and no foreign SPF keywords.
    * **`hybrid`**: Romanian IP address, but SPF explicitly authorizes foreign clouds (e.g. Google or Microsoft).
    * **`foreign`**: Mail server IP is outside Romania.
* **Geospatial Processing (`mapification.py`)**:
  * Joins the classification dataset with Romanian administrative polygon geometries (`ro_admin_lau_polygon.geojson`) into a unified `ro_mail_map.geojson`.
* **Interactive Frontend (`server.py` & `templates/index.html`)**:
  * Dark-mode Leaflet.js interactive map with color-coded polygons (Green = Local, Yellow = Hybrid, Red = Foreign, Grey = Unknown, Dark = No Data).
  * Interactive tooltips displaying municipality name, county, MX server, IP country, ISP, and foreign SPF directives.

---

### 3. ARP Cache Poisoning (`arp_spoofing/`)

Demonstration of layer-2 Man-in-the-Middle (MITM) positioning via ARP cache poisoning.

* **Poisoning Logic (`poison.py`)**:
  * Discovers physical MAC addresses for the gateway (`198.10.0.1`) and target (`198.10.0.2`) by sending broadcast ARP who-has requests (`ARP(op=1)`).
  * Continuously transmits unsolicited (gratuitous) ARP replies (`ARP(op=2)`) at 2-second intervals telling the target that the gateway's IP resides at the middle's MAC, and telling the gateway that the target's IP resides at the middle's MAC.
* **Network Restoration (`restore.py`)**:
  * Sends genuine ARP reply packets with correct hardware-to-IP pairings to restore normal switching/routing tables upon experiment completion.
* **Dedicated Testing Topology (`arp_spoofing/docker-compose.yaml`)**:
  * A standalone, isolated compose environment for verifying ARP poisoning without launching the full stack.

---

### 4. TCP Session Hijacking & Payload Injection (`tcp_hijacking/`)

An advanced attack demonstrating layer-4 TCP session hijacking and transparent HTTP content substitution.

* **Man-in-the-Middle Interception (`poison.py`)**:
  * Runs ARP cache poisoning in a background Python multiprocessing worker.
  * Inserts Linux `iptables` NFQUEUE rules for routed HTTP traffic:
    ```bash
    iptables -I FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 5
    iptables -I FORWARD -p tcp --sport 80 -j NFQUEUE --queue-num 5
    ```
* **Protocol Downgrade & Decompression**:
  * Inspects client HTTP requests (port 80).
  * Replaces `HTTP/1.1` with `HTTP/1.0` to eliminate persistent keep-alive chunking complications.
  * Replaces `Accept-Encoding: gzip, deflate` with `Accept-Encoding: identity     ` (padded to retain byte length), forcing web servers to return uncompressed HTML.
* **Payload Substitution & Sequence Number Resynchronization**:
  * When an HTTP response contains `src="unibuc_fisiere/header.jpg"`, it replaces the string with an external image URL (featuring a hyrax).
  * **Stateful TCP Offsetting**: Because the replacement URL length differs from the original, a byte offset is created:
    * Server-to-Client packets: adds `byte_offset` to `TCP.seq`.
    * Client-to-Server packets: subtracts `byte_offset` from `TCP.ack`.
  * Deletes IP and TCP checksums and lengths to force Scapy to recompute valid checksums.
  * Uses Scapy `send()` to inject the modified packet into the wire while dropping the original kernel packet.
* **Testing Infrastructure**:
  * Firefox running in Docker (`jlesage/firefox`) accessible via web VNC on port `5800`.
  * Custom enterprise policies (`policies.json`) locking down browser auto-updates and telemetry to ensure clean, observable network traffic.
  * Includes standalone socket scripts (`tcp_server.py` and `tcp_client.py`) for testing raw TCP payload manipulation.

---

### 5. Resilient DNS Tunneling (`dnstunnel/`)

Covert file transfer mechanism using DNS `TXT` queries and responses, engineered to be reliable over lossy UDP.

* **Protocol Specification**:
  * Domain: `tunnel.andrei12225.engineer`
  * Chunk Size: **180 bytes** raw data per chunk. When Base64-encoded, 180 bytes expands to ~240 characters, safely under the 255-byte limit for DNS TXT character-strings.
  * **Metadata Query**: `meta.<filename>.tunnel.andrei12225.engineer`
    * Response: `chunks:<total_chunks>:<file_md5_hash>`
  * **Data Query**: `buc<chunk_index>.<filename>.tunnel.andrei12225.engineer`
    * Response: Base64-encoded chunk data.
* **Server Implementation (`server/server.py`)**:
  * Authoritative UDP server listening on port `5002`.
  * Computes file MD5 hash using memory-efficient 8KB streaming reads.
  * Direct seek-and-read chunk retrieval (`f.seek(nr_buc * BUCSIZE)`).
* **Client Implementation (`flask/client.py`)**:
  * **Stop-and-Wait Reliability**: Requests each chunk sequentially. If a UDP packet is lost or times out (3-second socket timeout), it retries up to 3 times before applying an extended backoff.
  * **Resumable Downloads**: Checks `downloads/<filename>`. If a previous transfer was interrupted, it cleans any trailing corrupt or partial bytes via `truncate()`, calculates `already_written_bucati`, and resumes directly from the next required chunk index.
  * **Integrity Verification**: Calculates the local MD5 checksum of the assembled file and verifies it against the server's authoritative checksum received during metadata initialization.
* **Web UI & Streaming Dashboard (`flask/flask_server.py`)**:
  * Flask web interface on port `5001`.
  * Uses **Server-Sent Events (SSE)** (`text/event-stream`) to stream real-time transfer progress, retries, and checksum verification status to the user's browser without page reloads.

---

### 6. Project Dashboard Portal (`home_website/`)

* Built with Node.js and Express.
* Serves as the central landing page unifying all components.
* Provides direct navigation links, service status indicators, and overview documentation.

---

## 🚀 Getting Started

### Prerequisites

* **Operating System**: Linux (required for `iptables`, `netfilterqueue`, and network namespace features).
* **Docker**: Engine version 24.0+ and Docker Compose v2+.
* **System Utilities**: `dig`, `curl`, `python3` (for local verification).

### Starting the Full Stack

Clone the repository and spin up all services:

```bash
# Clone the repository
git clone https://github.com/retele-2023/proiect.git
cd ComputerNetworks

# Launch all microservices in the background
docker compose up --build -d
```

Verify that all containers are running:

```bash
docker compose ps
```

---

## 📁 Repository Directory Structure

```
.
├── docker-compose.yaml               # Master multi-service orchestration
├── README.md                         # Project documentation
│
├── AdBlockerDns/                     # DNS AdBlocker & Recursive Resolver
│   ├── udp_dns_server.py             # Dual-stack UDP server (port 53)
│   ├── recursive_resolver.py         # Iterative resolver with root traversal
│   ├── adresses.txt                  # Blocklist rules (60k+ domains)
│   ├── facebook.txt                  # Meta-specific tracker blocklist
│   ├── Dockerfile                    # Container configuration
│   └── DohEndpoint/                  # DNS-over-HTTPS Service
│       ├── doh_decoder.py            # FastAPI DoH RFC 8484 server
│       └── Dockerfile                # DoH container configuration
│
├── ad_stats/                         # Telemetry & Ad-Block Statistics
│   ├── app.py                        # Flask API & categorization engine
│   ├── Dockerfile                    # Container configuration
│   ├── data/                         # Persistent stats storage (stats.json)
│   └── templates/                    # Web dashboard frontend
│
├── mxmap/                            # Romanian Municipalities Mail Map
│   ├── get_info.py                   # Scapy DNS & ipinfo.io data extraction
│   ├── wikidata_query.txt            # SPARQL query for Romanian UATs
│   ├── mapification.py               # GeoJSON merger and classification script
│   ├── server.py                     # Flask web server
│   ├── query.csv                     # Raw Wikidata query results
│   ├── mail_classification.csv       # Extracted MX/SPF classification data
│   ├── ro_mail_map.geojson.zip       # Enriched map GeoJSON dataset
│   └── templates/index.html          # Interactive Leaflet.js frontend
│
├── arp_spoofing/                     # ARP Cache Poisoning Module
│   ├── poison.py                     # Scapy layer-2 ARP poisoner
│   ├── restore.py                    # Network ARP table restore utility
│   ├── docker-compose.yaml           # Standalone isolated testbed
│   ├── Dockerfile                    # Container definition
│   └── sh/                           # Routing configuration scripts
│
├── tcp_hijacking/                    # TCP Session Hijacking Module
│   ├── poison.py                     # NFQUEUE packet interceptor & payload injector
│   ├── policies.json                 # Firefox enterprise lockdown policies
│   ├── tcp_client.py                 # Low-level TCP test client
│   ├── tcp_server.py                 # Low-level TCP test server
│   ├── Dockerfile                    # Middle/Router/Client container
│   ├── server/                       # Target Firefox container
│   │   └── Dockerfile                # Based on jlesage/firefox with iproute2
│   └── sh/                           # Network route setup scripts
│
├── dnstunnel/                        # Covert DNS Tunneling System
│   ├── server/                       # Authoritative DNS UDP Server
│   │   ├── server.py                 # 180-byte Base64 chunk server
│   │   └── Dockerfile                # Server container definition
│   ├── flask/                        # Resilient Client & Web UI
│   │   ├── client.py                 # Stop-and-wait client with resume & MD5
│   │   ├── flask_server.py           # SSE streaming web server
│   │   ├── Dockerfile                # Client container definition
│   │   └── templates/                # Web UI template
│   ├── files/                        # Server source files (e.g. secret.txt)
│   └── downloads/                    # Client downloaded destination files
│
└── home_website/                     # Central Showcase Landing Portal
    ├── app.js                        # Node.js/Express server
    ├── package.json                  # Dependencies
    ├── Dockerfile                    # Container definition
    └── public/                       # Static web assets & styling
```

---

## 📜 Academic Context & License

This project was built for academic evaluation in the **Computer Networks (Rețele de Calculatoare 2025–2026)** course, taught at the Faculty of Mathematics and Computer Science, University of Bucharest.

All security tools and penetration testing techniques (ARP spoofing, session hijacking, DNS tunneling) are strictly for educational and defensive research purposes in isolated, containerized environments.
