# USI Software

## Running the Application

USI runs with two terminals: one for the public key directory server, and one for the GUI.

### Terminal 1: Start the Server

```bash
cd /Users/kusuma/Desktop/protocol/src/usi
go run ./server/main.go
```

### Terminal 2: Start the GUI

```bash
cd /Users/kusuma/Desktop/protocol/src/usi
go run ./cmd/main.go
```

The GUI auto-connects to the local USI public key directory server.

## Server Hardware Requirements

### Overview

The USI Public Key Directory Server is designed to run entirely on your own infrastructure. It does not require a cloud provider. You maintain control over your key directory, infrastructure, privacy, and data sovereignty.

The server is lightweight and suitable for:

- Home labs
- Small businesses
- Government deployments
- Air-gapped environments
- Enterprise internal PKI infrastructure
- Edge deployments
- Raspberry Pi clusters
- Old or repurposed hardware

### Minimum Specifications

| Component | Requirement | Notes |
| --- | --- | --- |
| CPU | 1 core, 1.5 GHz | Intel Celeron, AMD Athlon, ARM |
| RAM | 1 GB | DDR3 or DDR4 |
| Storage | 100 MB + 18 KB per organization | HDD supported |
| Network | 10 Mbps LAN or WAN | Local or internet-facing |
| Power | 5-15 watts | Very low consumption |
| OS | Linux, FreeBSD, macOS, Windows | Cross-platform |

### Recommended Specifications

| Component | Recommendation | Cost-effective options |
| --- | --- | --- |
| CPU | 2-4 cores at 2.5 GHz+ | Intel NUC, Dell OptiPlex |
| RAM | 4-8 GB | DDR3 or DDR4 memory |
| Storage | 120 GB+ SSD | SATA SSD recommended |
| Network | Gigabit Ethernet | Standard onboard NIC |
| Backup | Secondary disk or NAS | External HDD or NAS |
| Redundancy | Optional second node | High-availability deployments |

### Self-Hosted Hardware Examples

| Hardware | Specs | Cost | Max organizations |
| --- | --- | --- | --- |
| Raspberry Pi 4 | 4-core ARM, 4 GB RAM | $50-75 | 100,000+ |
| Raspberry Pi 5 | 4-core ARM, 8 GB RAM | $80-120 | 500,000+ |
| HP Thin Client T630 | AMD GX-420GI, 8 GB RAM | $60-100 | 200,000+ |
| ThinkPad T450 | Intel i5, 8 GB, SSD | $80-120 | 500,000+ |
| Intel NUC NUC7i3 | i3-7100U, 8 GB, SSD | $200-300 | 1,000,000+ |
| Dell OptiPlex Micro | i5-8500T, 16 GB | $250-350 | 2,000,000+ |
| HP EliteDesk Mini | i7-8700T, 16 GB | $300-400 | 5,000,000+ |
| Old gaming PC | Ryzen 5, 16 GB, SSD | $250-350 | 10,000,000+ |

### Performance Metrics

| Metric | Expected performance |
| --- | --- |
| Write speed | 40,000-60,000 ops/sec |
| Read speed | 80,000-90,000 ops/sec |
| Storage efficiency | About 18 KB per organization |
| 100,000 organizations | About 1.8 GB storage |

### Storage Considerations

HDD deployments are supported and suitable for small deployments. For production systems, SSD storage is recommended because it provides lower latency, faster LevelDB writes, better concurrent lookups, reduced fragmentation, and lower power consumption.

Disk speed test:

```bash
sudo hdparm -t /dev/sda
```

Expected results:

| Storage type | Throughput |
| --- | --- |
| HDD | About 100 MB/s |
| SSD | About 500 MB/s |
| NVMe | 1500+ MB/s |

### Network Requirements

USI can run fully inside a local network. Internet access is not required for local, intranet, VLAN, or air-gapped deployments.

For remote or internet-facing deployments, use:

- Port forwarding
- Static IP or Dynamic DNS
- VPN protection such as WireGuard, OpenVPN, or Tailscale

### Backup Strategy

Local backup example:

```bash
sudo cp -r /var/usi/server/pubkeydir.db /mnt/backup/pubkeydir_$(date +%Y%m%d)
```

Rsync replication example:

```bash
rsync -avz /var/usi/server/ user@backup-server:/var/usi/backup/
```

Scheduled backup example:

```cron
0 2 * * * /usr/local/bin/backup-usi.sh
```

## Installation

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y golang git

git clone https://github.com/ChyKusuma/protocol.git
cd protocol/src/usi

go build -o usi-server ./server/main.go

sudo cp usi-server /usr/local/bin/
sudo useradd -r -s /bin/false usi
sudo mkdir -p /var/usi/server
sudo chown usi:usi /var/usi/server
```

### systemd Service

Create the service file:

```bash
sudo nano /etc/systemd/system/usi-server.service
```

Service configuration:

```ini
[Unit]
Description=USI Public Key Directory Server
After=network.target

[Service]
Type=simple
User=usi
WorkingDirectory=/var/usi/server
ExecStart=/usr/local/bin/usi-server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable usi-server
sudo systemctl start usi-server
```

### Docker Deployment

Build the image:

```bash
docker build -t usi-server .
```

Run the container:

```bash
docker run -d \
  --name usi-server \
  -p 8080:8080 \
  -v /mnt/usi-data:/app/server \
  --restart unless-stopped \
  usi-server
```

## Deployment Summary

| Question | Answer |
| --- | --- |
| Can it run on old hardware? | Yes |
| Is SSD required? | No, but recommended |
| Raspberry Pi supported? | Yes |
| Internet required? | No |
| Windows supported? | Yes |
| Power usage? | Very low |
| Backup required? | Strongly recommended |

USI is designed to be lightweight, self-hosted, resource efficient, sovereign, air-gap compatible, low cost, and vendor independent.

No cloud dependency. No subscriptions. No vendor lock-in.

Your infrastructure. Your keys. Your sovereignty.

## Development Notes

- The GUI uses `app.NewWithID("com.usi.UniversalSovereignIdentity")`.
- The window title is `Universal Sovereign Identity`.
- The default window size is `1100x680`.
- Dark theme is enabled by default and can be toggled from the welcome/register screens.
- Sensitive operations ask the user to confirm their passphrase.
- Activity is tracked in-memory and displayed on the dashboard.
- Wallet operations are currently placeholders and should be connected to a real wallet backend.

## Security Notes

- Keep the generated passphrase private and backed up securely.
- Losing the passphrase can permanently lock encrypted vaults and private keys.
- Never share the private key files.
- Share only the public fingerprint or wallet address.
- Verify signatures using the original file and its matching `.usimeta` file.
- Confirm recipient fingerprints before encrypting shared vaults.

## License

Copyright (c) 2024-present Sphinx Core Dev

Released under the MIT License: <https://opensource.org/license/mit>
