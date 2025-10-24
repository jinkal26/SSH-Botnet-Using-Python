# SSH-Botnet-Using-Python


---


## Project Overview

This lab helps students and security teams practice detecting and responding to SSH-based botnet behaviors in a legal, controlled environment. The focus is on detection engineering, honeypots, network and host monitoring, incident response, and prevention strategies.

Key lab goals:

* Teach defenders typical botnet command-and-control (C2) patterns conceptually.
* Provide safe, rate-limited simulation scripts (lab-mode) that generate observable signals resembling botnet activity without enabling compromise or persistence.
* Offer hunting queries, Zeek/Suricata signatures, and SIEM rule examples to detect SSH brute-force campaigns, lateral movement, and anomalous SSH sessions.
* Show hardening best practices to prevent SSH-based intrusions.

---

## Components

* `lab-scripts/` — safe simulation scripts that generate observable behavior (e.g., coordinated timed SSH connection attempts to a lab honeypot, benign command execution recorded only in logs). All scripts require an explicit `--lab-mode` flag and enforce rate and scope limits.
* `honeypot/` — deployment guide for a low-interaction SSH honeypot (e.g., Cowrie or a simple containerized trap) configured to capture attacker activity without exposing real services.
* `detection/` — Zeek scripts, Suricata rules, and SIEM query examples to detect suspicious SSH behavior (credential guessing, anomalous session lengths, suspicious command sequences). Example rules are provided as pseudocode and mappings to Elastic/Kibana and Splunk query formats.
* `network-monitoring/` — PCAP capture examples, recommended Bro/Zeek logs to analyze, and Suricata rules for known malicious patterns.
* `playbooks/` — incident response playbooks for triage, containment, eradication, and recovery following an SSH-focused intrusion.
* `lab-setup/` — `docker-compose` scaffold to spin up an isolated lab: a honeypot, log collector (ELK stack or alternative), and a controlled "C2 simulator" receiver used solely for detection exercises.
* `test-data/` — synthetic, non-sensitive artifacts used by simulations; no real credentials or PII are included.

---

## Learning Objectives

Participants will learn to:

* Recognize common SSH-based attack patterns (credential stuffing, brute force, lateral movement, use of compromised credentials).
* Deploy and configure honeypots safely to capture attempted intrusions for analysis.
* Create detection rules and hunting queries for suspicious SSH activity (failed auth spikes, unusual source IPs, abnormal session durations, interactive TTY-less sessions).
* Use network and host logs (auditd, SSH server logs, Zeek conn.log, auth.log) to reconstruct attacker activity.
* Harden SSH services: disable root login, require key-based auth, use MFA, limit source IPs, and monitor for anomalous logins.

---

## Safe Simulation Scripts (High-level)

All simulation scripts are intentionally non-malicious and include multiple safeguards. They are designed to *emulate observable patterns* of malicious campaigns without performing unauthorized access or creating persistence.

Safety controls built into scripts:

* Mandatory `--lab-mode` flag to prevent accidental runs
* Explicit whitelist of lab-controlled IPs and honeypot endpoints in `lab-config.yml`
* Rate limiting to avoid flooding target services
* Small, synthetic workloads and non-sensitive test data
* No code for exploitation, persistence, lateral movement, or real credential use

Example lab behaviors (safe):

* `simulate_credential_stuffing.py` — performs timed, low-volume authentication attempts using a synthetic credential list against a local honeypot only; logs attempts and metrics for SIEM ingestion.
* `simulate_c2_beacon.py` — generates periodic DNS and HTTP requests to a lab-only C2 sink to model beacon patterns for detection exercises.
* `simulate_lateral_scan.py` — simulates discovery-level scanning (port probe signals) to generate network telemetry; targets are lab VMs only and rate-limited.

Each script is documented and commented to emphasize detection signals and the defensive controls they exercise.

---

## Detection Guidance & Example Rules

Provided as high-level pseudocode and example queries for popular SIEMs. Topics covered:

* **Brute-force / credential stuffing:** Alert on hosts with a spike in `sshd` failed authentication events or many unique source IPs attempting logins to a single account.
* **Unusual interactive sessions:** Alert on SSH sessions that spawn unexpected command sequences or create reverse tunnels.
* **Anomalous TTY-less connections:** Many botnets and automated tools use non-interactive sessions; alert on non-tty sessions that execute network or file-transfer commands.
* **Beacon detection:** Look for periodic, low-volume external connections from endpoints that don’t normally contact outside services.

Example Elastic-style query (pseudocode):

```
index=auth_logs event=sshd AND (action=failed_auth) | stats count() by src_ip, user | where count() > 50
```

Example Zeek signatures and Suricata rules are included in `detection/` as safe, non-actionable examples.

---


## Hardening & Mitigation Best Practices

Use the lab to demonstrate and practice the following defenses:

* Enforce key-based SSH authentication and disable password-based auth where possible.
* Disable direct root login (`PermitRootLogin no`) and use `AllowUsers` / `AllowGroups` to restrict access.
* Implement rate-limiting at the SSH service or network level (fail2ban, firewall rules, connection throttling).
* Require multifactor authentication for remote access.
* Monitor auth logs (`/var/log/auth.log`), enable host-based auditing (auditd), and ship logs to a central SIEM for correlation.
* Rotate credentials and follow least privilege for service accounts.

---

## Incident Response Playbook (Summary)

1. **Detect:** Confirm alerts from SIEM/honeypot/IDS and collect relevant logs and PCAPs.
2. **Triage:** Identify affected accounts, source IPs, and scope of attempted access.
3. **Contain:** Block malicious source IPs, isolate affected hosts, and disable compromised accounts.
4. **Eradicate:** Remove backdoors, unauthorized keys, and artifacts; re-image hosts if necessary.
5. **Recover:** Re-enable services with hardened configuration and rotated credentials.
6. **Postmortem:** Update detection rules, hardening guidance, and run tabletop exercises.

---

## Lab Setup (Quick Start)

1. Clone the repository and inspect `lab-config.yml` to ensure all endpoints are local to the lab.

```bash
git clone https://github.com/<your-username>/ssh-botnet-sim-lab.git
cd ssh-botnet-sim-lab
```

2. Start the lab stack with Docker Compose (example brings up honeypot, Zeek, and an ELK stack):

```bash
docker-compose up --build
```

3. Run a safe simulation (requires `--lab-mode`):

```bash
python3 lab-scripts/simulate_credential_stuffing.py --lab-mode --honeypot localhost:2222 --rate 1
```

4. Observe alerts and logs in the SIEM, and practice triage and response using the provided playbooks.

---

## Ethical Guidance

* Only run simulations in lab environments or under explicit written authorization.
* Use synthetic data only and never reuse real credentials or PII.
* Keep experiments documented and limited in scope to avoid accidental harm.

---

## Extending the Lab

* Integrate automated scoring for red-team/blue-team exercises.
* Add advanced behavioral analytics (user- and host-based baselines) to increase detection fidelity.
* Implement SOAR playbooks to automate containment actions in the lab.

---

## Contributing

Contributions that improve defensive capabilities, clarify detection guidance, or add safe lab scenarios are welcome. Open issues or PRs and include tests and documentation updates.

---

## License

MIT License — see `LICENSE` for details.

---

Created by Inlighn Tech to provide a safe, educational approach to understanding and detecting SSH-based botnet behaviors. Thanks to the security community for best practices and tooling inspiration.
