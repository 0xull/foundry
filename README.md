# Foundry Container Runtime

**Foundry** is a purpose-built, educational container runtime and software-defined networking (SDN) implementation. It is designed to deconstruct and rebuild the core primitives of modern cloud infrastructure: OCI-compliant container execution, CNI networking orchestration, and high-performance packet processing using eBPF/XDP.

This repository contains two distinct subsystems:

1. **Foundry Runtime (Rust):** A client/server architecture for managing container lifecycles (namespaces, cgroups, chroot).
2. **Foundry Data Plane (Go/C):** A high-performance forwarding plane leveraging XDP (eXpress Data Path) to handle container traffic in the kernel.

## 1. System Architecture

The project follows a split-binary architecture to separate user interaction from state management, further extended by a dedicated programmable data plane.

### Core Components

* **`foundry` (Client):** A stateless "thin client" CLI. It parses user arguments and transmits them via JSON-RPC over a Unix Domain Socket.
* **`foundryd` (Daemon):** A long-running background service managed by `systemd`. It creates and holds the state of all containers. It is responsible for:
* Parsing OCI Bundles (`config.json`).
* Setting up Linux Namespaces (PID, UTS, MNT, NET).
* Configuring Control Groups (cgroups v2) for resource limiting.
* Invoking CNI plugins to configure network interfaces.


* **XDP Forwarder (Data Plane):** An eBPF program attached to the host-side `veth` interfaces. It currently functions as a transparent Layer 2 bridge, bypassing the host kernel's TCP/IP stack to forward packets between isolated namespaces.


## 2. Directory Structure

```plaintext
.
├── src/
│   ├── bin/
│   │   └── foundry.rs      # CLI Client entry point
│   └── main.rs             # Daemon (foundryd) entry point & core logic
├── xdp-forwarder/          # [Active] eBPF Data Plane implementation
│   ├── forwarder.c         # XDP C source code (Kernel Land)
│   ├── main.go             # Go Loader & Lifecycle Manager (User Land)
│   ├── gen.go              # bpf2go generation directive
│   └── setup-lab.sh        # Network namespace topology setup script
├── Cargo.toml              # Rust project definition
├── foundryd.service        # systemd unit file
└── README.md               # Documentation

```

## 3. Prerequisites

To build and run the full stack, the following toolchains are required:

**System Dependencies:**

* **Linux Kernel 5.10+** (Required for modern BPF features)
* **Clang & LLVM:** For compiling C to eBPF bytecode.
* **libbpf-dev:** Development headers for BPF.

**Languages:**

* **Rust (Latest Stable):** For the runtime engine.
* **Go (1.20+):** For the BPF loader and future SDN agent.

## 4. Building and Running

### Part A: The Runtime (`foundry`)

1. **Build the binaries:**
```bash
cargo build --release

```


2. **Install to system path:**
```bash
sudo install ./target/release/foundryd /usr/local/bin/
sudo install ./target/release/foundry /usr/local/bin/

```


3. **Start the Daemon via systemd:**
```bash
sudo cp foundryd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now foundryd

```


4. **Interaction:**
```bash
# Create a container from an OCI bundle
foundry create --bundle-path /path/to/bundle --container-id test-1

# Start the container
foundry start --container-id test-1

```



### Part B: The Data Plane (`xdp-forwarder`)

Currently, the data plane acts as a standalone L2 forwarder for verification purposes.

1. **Navigate to the module:**
```bash
cd xdp-forwarder

```


2. **Generate BPF Artifacts:**
This step uses `bpf2go` to compile `forwarder.c` against the host headers.
```bash
go generate

```


3. **Setup the Verification Lab:**
Creates two network namespaces (`netns1`, `netns2`) connected via veth pairs to the host.
```bash
sudo ./setup-lab.sh

```


4. **Run the Loader:**
Loads the XDP program into the kernel and attaches it to the host-side veth interfaces.
```bash
go build -o loader
sudo ./loader

```


5. **Verify Forwarding:**
Open a separate terminal to monitor traffic while the loader is running:
```bash
# Ping from netns1 to netns2 (simulating container-to-container traffic)
sudo ip netns exec netns1 ping 10.0.0.2

```


## 5. Development Roadmap

The project is currently in **Phase 3: The Data Plane**. Below is the immediate implementation schedule.

### [Completed] Month 3, Week 1: The XDP Forwarder

* **Objective:** Implement transparent L2 forwarding in eBPF.
* **Status:** Functional.
* **Capabilities:**
* Parses Ethernet frames in kernel space.
* Performs MAC address rewriting (Source/Dest swapping).
* Redirects packets between interfaces using `bpf_redirect` (Egress).



### [Upcoming] Month 3, Week 2: The Overlay Network (VXLAN)

* **Objective:** Evolve the forwarder into a Virtual Tunnel Endpoint (VTEP).
* **Technical Implementation:**
* Implement `bpf_xdp_adjust_head` to resize packet buffers.
* **Encapsulation:** Wrap inner Ethernet frames with outer IP/UDP/VXLAN headers.
* **Decapsulation:** Parse incoming VXLAN packets, validate VNI, and strip headers.
* Support for RFC 7348 VXLAN packet structure.



### [Upcoming] Month 3, Week 3: Dynamic Forwarding (eBPF Maps)

* **Objective:** Remove hardcoded logic and implement a Forwarding Database (FDB).
* **Technical Implementation:**
* **FDB Map:** `BPF_MAP_TYPE_HASH` storing `[VNI, MAC] -> [Type, RemoteIP/IfIndex]`.
* **Lookups:** Logic to distinguish between LOCAL (direct redirect) and REMOTE (VXLAN encap) traffic.
* **Control Plane:** Go loader acts as the initial map population tool.



### [Upcoming] Month 3, Week 4: The SDN Agent

* **Objective:** Create a long-running daemon to manage the data plane lifecycle.
* **Technical Implementation:**
* **gRPC API:** Define `agent.proto` for adding/removing forwarding entries.
* **Lifecycle Management:** Handle loading XDP programs and pinning BPF maps (`/sys/fs/bpf/`).
* **Persistence:** Ensure map state survives process restarts via BPF filesystem pinning.
