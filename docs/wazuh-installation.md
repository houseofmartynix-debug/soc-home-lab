# Wazuh All-in-One Installation

Reference: [Wazuh quickstart installation](https://documentation.wazuh.com/current/quickstart.html).

## Target Host

- Ubuntu Server 22.04 LTS
- 4 vCPU, 8 GB RAM, 50 GB disk
- Static IP `10.0.0.10`
- Open ports: `443/tcp` (dashboard), `1514/tcp` (agents), `1515/tcp` (enrollment), `514/udp` (syslog)

## Install

```bash
# Update base
sudo apt update && sudo apt upgrade -y

# Run Wazuh installer (manager + indexer + dashboard)
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

The installer prints the initial **admin** password — save it in a password manager. Login at `https://10.0.0.10/`.

## Post-Install Hardening

1. **Change admin password** in the Wazuh dashboard → Security → Users.
2. **Restrict SSH** to the analyst subnet only.
3. **Enable automatic security updates** on the manager host:
   ```bash
   sudo apt install -y unattended-upgrades
   sudo dpkg-reconfigure --priority=low unattended-upgrades
   ```
4. **Back up** `/var/ossec/etc/` and `/etc/wazuh-indexer/` weekly.

## Where the Important Files Live

| Path | Purpose |
|---|---|
| `/var/ossec/etc/ossec.conf` | Manager configuration |
| `/var/ossec/etc/rules/local_rules.xml` | Native space for custom rules |
| `/var/ossec/etc/decoders/local_decoder.xml` | Custom decoders |
| `/var/ossec/logs/alerts/alerts.json` | All alerts (JSON, one per line) |
| `/var/ossec/logs/archives/archives.json` | All events (if `<logall_json>` enabled) |

## Loading Custom Rules from This Repo

```bash
# Copy
sudo cp detection-rules/wazuh-custom-rules/*.xml /var/ossec/etc/rules/

# Validate syntax
sudo /var/ossec/bin/wazuh-logtest -t

# Restart
sudo systemctl restart wazuh-manager

# Tail alerts to confirm
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

## Testing a Rule

Use `wazuh-logtest` to feed a sample event and confirm a rule fires:

```bash
sudo /var/ossec/bin/wazuh-logtest
> Type log:
Apr 24 10:00:00 ubuntu-01 sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
```

Expected output includes the matched rule id and level.
