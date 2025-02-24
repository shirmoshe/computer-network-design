# Computer Network Design Labs 
This repository contains a collection of labs and a final project completed as part of the **Computer Network Design** course at **Ben-Gurion University**. The labs cover various networking protocols and configurations using tools like **GNS3**, **Wireshark**, and **Cisco Routers**, while the final project focuses on implementing an **Encrypted Multicast Chat** using **Diffie-Hellman key exchange** over **TCP/UDP**.

---

## Lab List

### Lab 1 – DHCP & VLAN Configuration
- Configured **Dynamic Host Configuration Protocol (DHCP)** on Cisco routers.
- Implemented **VLANs** for logical network segmentation.
- Used **Wireshark** to capture DHCP packets and analyze the DHCP handshake.

### Lab 2 – MPLS (Multiprotocol Label Switching)
- Set up **MPLS** networks with **OSPF** as the underlying routing protocol.
- Explored **Label Distribution Protocol (LDP)** and analyzed MPLS packet flow using **Wireshark**.
- Compared routing via MPLS labels vs. traditional IP routing.

### Lab 3 – Internal & External BGP (iBGP/eBGP)
- Configured **Internal BGP (iBGP)** and **External BGP (eBGP)** peers across multiple Autonomous Systems (AS).
- Implemented route advertisements and used **Wireshark** to inspect BGP sessions.
- Practiced BGP route filtering and failover mechanisms.

### Lab 4 – PIM-SM & Multicast Routing
- Implemented **Protocol Independent Multicast - Sparse Mode (PIM-SM)** on Cisco routers.
- Explored **Multicast Routing** and configured **IGMP** to manage multicast group memberships.
- Verified multicast data flows using **Wireshark**.

### Lab 5 – RTP/RTCP Streaming
- Streamed **audio files** using **RTP (Real-time Transport Protocol)** and monitored **RTCP** control messages.
- Simulated **packet loss** and analyzed its effect on real-time streaming.
- Compared **TCP** vs. **UDP** performance in streaming scenarios.

---

## Final Project – Encrypted Multicast Chat 

**Project Goal:**  
To design and implement a secure, encrypted multicast chat system using **Diffie-Hellman (DH)** key exchange over **TCP/UDP** sockets.

**Key Features:**
- **Diffie-Hellman Key Exchange:** Securely establishes shared keys between server and clients.
- **Multicast Group Chat:** Uses **UDP Multicast** for broadcasting encrypted messages.
- **TCP Communication:** Manages key exchanges and keep-alive messages.
- **Encryption/Decryption:** Messages are encrypted using shared keys before transmission.
- **Timeout Mechanism:** Clients are disconnected if no keep-alive messages are received within a set period.

**Technologies Used:**
- **Languages:** C (for both client and server)
- **Networking:** TCP/UDP Sockets, Multicast, Diffie-Hellman Key Exchange
- **Tools:** Wireshark (for packet analysis)

---
## Requirements

**General Tools & Software**:
- GNS3 – For network simulations and router configurations.
- Wireshark – For network traffic analysis and packet inspection.
- Cisco Packet Tracer – (Optional) for simpler network simulations.
- gcc (Gnu Compiler Collection) – To compile the C code for the final project.
- Linux-based OS – Ubuntu recommended for socket programming and compilation.

**Libraries & Dependencies:**
- POSIX Threads (pthreads) – For multi-threaded server-client communication.
- Math Library (-lm) – For mathematical operations in Diffie-Hellman key exchange.
- Socket Libraries – Standard C libraries for TCP/UDP communication (sys/socket.h, netinet/in.h, etc.).
---
