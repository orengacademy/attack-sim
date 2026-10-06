# Module reference — what each attack tests & how to block it

> Auto-generated from each module's `META` + docstring by `additional/gen_module_docs.py` — regenerate after changing a module; don't hand-edit. Tags: `[original]` = in the default 11-module set, `[added]` = opt-in.

**Reading the verdict:** SUCCESS = the attack reached/worked (a finding — the control did NOT stop it); BLOCKED = a control stopped it (green); DETECTED = it passed but the SOC/appliance alerted; NO-SERVICE = the port/service wasn't there; SKIPPED = needs config/creds it didn't have; NO-RESULT = inconclusive (read the raw log).

**51 modules** across 7 categories. `control` = how to prevent it; `fix` = who owns the fix (SD-WAN / Server / Agency).

## Contents
- **AD Exploitation** (9)
- **Application Control** (10)
- **Egress / C2** (7)
- **Exfiltration** (3)
- **Network Exploitation** (10)
- **Segmentation** (8)
- **Server Exploitation** (4)


## AD Exploitation

### DCSync  `dcsync`  _[original]_

- **Scope:** pentest · direction a2b · ports 445/tcp, 135/tcp · MITRE T1003.006
- **What it tests / why:** DCSync via impacket-secretsdump. Tests segmentation (RPC replication).
- **Control it validates (how to PREVENT / BLOCK):** Segmentation (RPC replication)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** python: impacket; DC creds

### LDAP Null Bind  `ldap_null_bind`  _[original]_

- **Scope:** va · direction a2b · ports 389/tcp · MITRE T1087.002 · CWE-306
- **What it tests / why:** LDAP null/anonymous bind. Discloses AD naming context without any credentials — matches the manual test script's ldapsearch check exactly.
- **Control it validates (how to PREVENT / BLOCK):** Anonymous LDAP bind hardening
- **Fix (owner / remediation):** Server
- **Needs to run:** tools: ldapsearch

### PsExec Lateral Movement  `psexec`  _[original]_

- **Scope:** attack_sim/D · direction a2b · ports 445/tcp · MITRE T1021.002, T1569.002
- **What it tests / why:** PsExec lateral movement via impacket-psexec. Tests SMB/RPC segmentation + IPS PsExec signature. Needs valid admin creds (core.DEFAULT_CREDENTIALS) and SMB (445) reachable to the target.
- **Control it validates (how to PREVENT / BLOCK):** Segmentation (SMB/RPC) + IPS signature
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** python: impacket; DC creds

### sAMAccountName Spoofing (CVE-2021-42278)  `samaccountname_spoof`  _[original]_

- **Scope:** pentest · direction a2b · ports 389/tcp, 445/tcp · MITRE T1136.002, T1078.002 · CWE-290
- **What it tests / why:** sAMAccountName Spoofing (CVE-2021-42278) — standalone, isolated from the S4U2Self escalation chain (see modules/nopac.py for that). Tests ONE specific control: does AD let a low-privileged user (a) create a computer account via SAMR (gated by ms-DS-MachineAccountQuota) and then (b) rename its sAMAccountName, via a plain LDAP modify, to collide with an existing DC's name minus the trailing "$"?
- **Control it validates (how to PREVENT / BLOCK):** ms-DS-MachineAccountQuota / sAMAccountName uniqueness validation
- **Fix (owner / remediation):** Set ms-DS-MachineAccountQuota=0; reject computer-account renames that collide with an existing DC name
- **Needs to run:** python: impacket, ldapdomaindump, dns.asyncquery; DC creds

### Kerberoast  `kerberoast`  _[added]_

- **Scope:** pentest · direction a2b · ports 88/tcp, 389/tcp · MITRE T1558.003 · CWE-522
- **What it tests / why:** Kerberoast via impacket-GetUserSPNs. Fix = AD hardening (NOT SD-WAN).
- **Control it validates (how to PREVENT / BLOCK):** AD hardening (NOT SD-WAN)
- **Fix (owner / remediation):** Server
- **Needs to run:** python: impacket; DC creds

### Kerberos AS-REP Roast  `kerberos_asrep`  _[added]_

- **Scope:** pentest · direction a2b · ports 88/tcp · MITRE T1558.004 · CWE-522
- **What it tests / why:** Kerberos AS-REP roasting (A -> B DC). Unlike Kerberoast, this needs NO credentials: it asks the KDC for an AS-REP for each candidate user and any account with pre-auth disabled (DONT_REQ_PREAUTH) returns a roastable $krb5asrep$ hash. It's the better no-cred test of whether the SD-WAN exposes / permits Kerberos attack traffic (88) toward the KVDC domain controller.
- **Control it validates (how to PREVENT / BLOCK):** Segmentation to DC / Kerberos exposure (88)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** python: impacket; DC creds

### noPac (CVE-2021-42278 + CVE-2021-42287)  `nopac`  _[added]_

- **Scope:** pentest · direction a2b · ports 389/tcp, 445/tcp, 88/tcp · MITRE T1068, T1078 · CWE-290
- **What it tests / why:** noPac ("Sam-The-Admin": CVE-2021-42278 sAMAccountName spoofing + CVE-2021-42287 KDC/S4U2Self PAC-lookup fallback). A low-privileged domain user creates a computer account, temporarily renames it to a DC's name minus the trailing "$", requests a TGT, then abuses S4U2Self so the KDC's PAC lookup resolves to the real DC's identity — yielding a service ticket that impersonates a Domain Admin. Tests ms-DS-MachineAccountQuota and PAC validation, not network segmentation.
- **Control it validates (how to PREVENT / BLOCK):** ms-DS-MachineAccountQuota / KDC PAC validation
- **Fix (owner / remediation):** Nov 2021 cumulative update (patches CVE-2021-42287); set ms-DS-MachineAccountQuota=0 as a mitigating control
- **Needs to run:** python: impacket, ldapdomaindump, dns.asyncquery; DC creds

### PetitPotam NTLM Coercion  `petitpotam`  _[added]_

- **Scope:** pentest · direction a2b · ports 445/tcp · MITRE T1187 · CWE-294
- **What it tests / why:** PetitPotam (MS-EFSRPC) NTLM coercion. Coerces the DC's machine account to authenticate back to this Kali host over SMB, captured by Responder — the same two-process chain as the manual test (Responder listening, PetitPotam triggering the callback). Responder needs root (privileged port binds + raw poisoning); this module self-elevates it via `sudo -n responder` when you're not root — so run the harness as your normal user (NOT `sudo python3 gui.py`) and give responder a NOPASSWD sudoers rule.
- **Control it validates (how to PREVENT / BLOCK):** SMB signing / NTLM relay & outbound-auth protections
- **Fix (owner / remediation):** Server
- **Needs to run:** tools: responder, python3; **root**; DC creds

### WMI Lateral Movement  `wmiexec`  _[added]_

- **Scope:** attack_sim/D · direction a2b · ports 445/tcp, 135/tcp · MITRE T1047
- **What it tests / why:** WMI lateral movement via impacket, called in-process (not the impacket-wmiexec CLI) so modules/_portpatch.py + modules/_dcompatch.py can transparently redirect the connection when the target is a NAT'd lab host (see test2.py / modules/_portpatch.py for the SMB(445)/RPC(135) leg, and modules/_dcompatch.py for why WMI additionally needs its own fix: DCOM's OXID resolver hands back the *server's own internal address* for every COM object it creates — 192.168.122.x here, not the droplet's public IP — and impacket only accepts a string binding whose address matches the target we connected with. _dcompatch rewrites that address to target_ip, keeping the (already-forwarded, same dynamic range DCSync uses) port.
- **Control it validates (how to PREVENT / BLOCK):** Segmentation (SMB/RPC/DCOM) + IPS/EDR WMI-exec detection
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** python: impacket.examples.secretsdump; DC creds


## Application Control

### App-ID Protocol/Port Mismatch  `appid_port_mismatch`  _[added]_

- **Scope:** attack_sim/D · direction a2b · ports — (no target port; egress / ICMP) · MITRE T1571 · CWE-923
- **What it tests / why:** Application-ID / protocol-port mismatch (A -> B). Sends a deliberately WRONG L7 protocol into an allowed port (SSH banner into an HTTP port, HTTP request into the SSH port). If the flow establishes and bytes move, the SD-WAN is enforcing by PORT only, not by application identity — i.e. App-ID is not catching the mismatch, which is a policy-bypass finding.
- **Control it validates (how to PREVENT / BLOCK):** Application-ID / L7 policy (not port-based)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** nothing (just a reachable target)

### Covert Channel (ICMP/DNS tunneling)  `covert_channel`  _[added]_

- **Scope:** attack_sim/E · direction a2b · ports icmp · MITRE T1572, T1048.003 · CWE-693
- **What it tests / why:** Covert-channel / tunneling test (A -> B). Checks whether two out-of-band channels are open through the SD-WAN:
- **Control it validates (how to PREVENT / BLOCK):** Covert-channel / DNS-egress control
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** tools: ping, dig; config.json: attacker_domain, canary_dns_zone

### Exposed Management / API Surface (443)  `exposed_mgmt_api`  _[added]_

- **Scope:** attack_sim/F · direction a2b · ports 443/tcp · MITRE T1133, T1596 · CWE-200
- **What it tests / why:** Family F — exposed management / API surface on 443 inbound.
- **Control it validates (how to PREVENT / BLOCK):** No management surface published; mTLS on sensitive APIs; modern TLS
- **Fix (owner / remediation):** Agency (WAF/app)
- **Needs to run:** config.json: published_app_url

### HTTP Request Smuggling / Desync (probe)  `http_smuggling`  _[added]_

- **Scope:** attack_sim/C · direction a2b · ports 443/tcp · MITRE T1190 · CWE-444
- **What it tests / why:** Family C — HTTP request-smuggling / desync probe (safe, single-shot).
- **Control it validates (how to PREVENT / BLOCK):** Consistent HTTP parsing (reject ambiguous CL/TE)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** config.json: published_app_url

### TLS Fingerprint Mimicry (JA3/JA4)  `ja3_mimicry`  _[added]_

- **Scope:** attack_sim/C · direction a2b · ports 443/tcp · MITRE T1573 · CWE-923
- **What it tests / why:** Family C — TLS fingerprint mimicry (JA3/JA4).
- **Control it validates (how to PREVENT / BLOCK):** Behavioural NDR beyond TLS fingerprints; TLS inspection
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** config.json: attacker_vps

### L4-vs-L7 Enforcement (443)  `l7_enforce_443`  _[added]_

- **Scope:** attack_sim/A · direction a2b · ports 443/tcp · MITRE T1095, T1071.001 · CWE-923
- **What it tests / why:** L4-vs-L7 enforcement on 443 — sends deliberately NON-TLS bytes to 443. A port-only firewall forwards anything on 443; an application-aware boundary should reset a 443 session that isn't valid TLS. If the peer accepts/holds the non-TLS session, the boundary is NOT enforcing L7 — exactly the gap raw-TCP tunnels (chisel/gost) exploit. Adapted from additional/mygovnet_egress_probe.py (test_l7).
- **Control it validates (how to PREVENT / BLOCK):** Application-ID / L7 enforcement on 443
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** nothing (just a reachable target)

### NRD / Uncategorised-domain Egress  `nrd_category`  _[added]_

- **Scope:** attack_sim/C · direction a2b · ports — (no target port; egress / ICMP) · MITRE T1090.002, T1583.001 · CWE-693
- **What it tests / why:** Family C — reputation / category laundering (newly-registered & uncategorised).
- **Control it validates (how to PREVENT / BLOCK):** Block newly-registered / uncategorised destinations (443)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** config.json: attacker_domain

### Direct-to-internet Egress (proxy bypass)  `proxy_bypass`  _[added]_

- **Scope:** attack_sim/C · direction a2b · ports — (no target port; egress / ICMP) · MITRE T1090 · CWE-923
- **What it tests / why:** Family C — direct-to-internet egress (authenticated-proxy bypass).
- **Control it validates (how to PREVENT / BLOCK):** Enforce authenticated proxy for all egress (no direct path)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** config.json: attacker_vps

### TLS Carrier (443)  `tls_carrier`  _[added]_

- **Scope:** attack_sim/A · direction a2b · ports 443/tcp · MITRE T1071.001
- **What it tests / why:** TLS carrier on 443 — completes a TLS handshake and reads the peer cert. Confirms 443 is a usable encrypted carrier that tunnels/C2 (Cloudflare Tunnel, ngrok, chisel, many C2s) ride on, and reveals a TLS-inspecting proxy substituting its own cert. Adapted from additional/mygovnet_egress_probe.py (test_tls).
- **Control it validates (how to PREVENT / BLOCK):** TLS egress / C2 carrier on 443
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** nothing (just a reachable target)

### WAF Evasion (published 443 app)  `waf_evasion`  _[added]_

- **Scope:** attack_sim/F · direction a2b · ports 443/tcp · MITRE T1190 · CWE-20
- **What it tests / why:** Family F — WAF evasion on a published 443 app.
- **Control it validates (how to PREVENT / BLOCK):** Normalising WAF; anomaly scoring; virtual patching
- **Fix (owner / remediation):** Agency (WAF)
- **Needs to run:** config.json: published_app_url


## Egress / C2

### Malleable C2 Beacon Shaping  `beacon_shaping`  _[added]_

- **Scope:** attack_sim/G · direction a2b · ports — (no target port; egress / ICMP) · MITRE T1071.001, T1573 · CWE-693
- **What it tests / why:** Family G — malleable C2 beacon shaping (NDR beacon-analytics test overlay).
- **Control it validates (how to PREVENT / BLOCK):** Statistical beacon detection (NDR) tolerant of jitter; UEBA
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** **--active** (live establishment); config.json: attacker_vps, beacon_interval, beacon_seconds, canary_url

### Domain Fronting / SNI≠Host  `domain_fronting`  _[added]_

- **Scope:** attack_sim/A · direction a2b · ports — (no target port; egress / ICMP) · MITRE T1090.004 · CWE-693
- **What it tests / why:** Family A — Domain fronting / SNI-vs-Host mismatch.
- **Control it validates (how to PREVENT / BLOCK):** TLS inspection reads true Host (not SNI-only filtering)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** config.json: front_domain, front_host

### 443 Tunnel-broker Egress (cloudflared/ngrok/…)  `egress_tunnel_brokers`  _[added]_

- **Scope:** attack_sim/A · direction a2b · ports — (no target port; egress / ICMP) · MITRE T1572, T1071.001 · CWE-693
- **What it tests / why:** Family A — Encrypted C2 & tunnelling over 443 (egress domain allow-listing test).
- **Control it validates (how to PREVENT / BLOCK):** Egress domain allow-listing / tunnel-category filtering (443)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** nothing (just a reachable target)

### LOTS SaaS C2 Egress (GitHub/Graph/Slack/…)  `lots_saas_c2`  _[added]_

- **Scope:** attack_sim/A · direction a2b · ports — (no target port; egress / ICMP) · MITRE T1102, T1071.001 · CWE-693
- **What it tests / why:** Family A — Living-off-trusted-sites (LOTS) C2 reachability.
- **Control it validates (how to PREVENT / BLOCK):** CASB / consumer-SaaS egress control (443)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** config.json: lots_saas

### Self-hosted Tunnel to VPS (chisel/gost, 443)  `self_tunnel_vps`  _[added]_

- **Scope:** attack_sim/A · direction a2b · ports — (no target port; egress / ICMP) · MITRE T1090.003, T1572 · CWE-693
- **What it tests / why:** Family A — Self-hosted reverse tunnel to an operator VPS on 443.
- **Control it validates (how to PREVENT / BLOCK):** Egress category filtering + L7/App-ID on 443 (uncategorised host)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** **--active** (live establishment); config.json: attacker_vps

### SSH-over-443 (dynamic SOCKS)  `ssh_over_443`  _[added]_

- **Scope:** attack_sim/A · direction a2b · ports — (no target port; egress / ICMP) · MITRE T1572, T1048 · CWE-923
- **What it tests / why:** Family A — SSH-over-443 (+ dynamic SOCKS).
- **Control it validates (how to PREVENT / BLOCK):** App-ID on 443 (deny non-HTTPS) + SSH client egress control
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** **--active** (live establishment); config.json: attacker_vps

### UDP/443 (QUIC) Egress  `udp443_quic`  _[added]_

- **Scope:** attack_sim/A · direction a2b · ports 443/udp · MITRE T1572 · CWE-693
- **What it tests / why:** Family A — UDP/443 (QUIC / HTTP-3) egress.
- **Control it validates (how to PREVENT / BLOCK):** Default-deny UDP/443 (QUIC) egress
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** config.json: attacker_vps


## Exfiltration

### DLP Canary Exfil (HTTPS POST)  `dlp_canary_https`  _[added]_

- **Scope:** attack_sim/E · direction a2b · ports — (no target port; egress / ICMP) · MITRE T1567.002 · CWE-200
- **What it tests / why:** Family E — DLP: canary-token HTTPS POST to cloud/SaaS storage.
- **Control it validates (how to PREVENT / BLOCK):** DLP content inspection + CASB SaaS-egress control
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** config.json: canary_url

### DLP Low-and-slow Exfil (chunked)  `dlp_lowandslow`  _[added]_

- **Scope:** attack_sim/E · direction a2b · ports — (no target port; egress / ICMP) · MITRE T1030, T1027 · CWE-200
- **What it tests / why:** Family E — DLP: low-and-slow / chunked exfil under volume thresholds.
- **Control it validates (how to PREVENT / BLOCK):** Cumulative/volume-over-time DLP; UEBA per-user egress baselines
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** **--active** (live establishment); config.json: canary_url

### ICMP Exfiltration (marked payload)  `icmp_exfil`  _[added]_

- **Scope:** attack_sim/E · direction a2b · ports icmp · MITRE T1048.003 · CWE-693
- **What it tests / why:** Family E — ICMP exfiltration channel (marked canary payload).
- **Control it validates (how to PREVENT / BLOCK):** Restrict/monitor outbound ICMP; volumetric analytics
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** tools: ping; **--active** (live establishment); config.json: attacker_vps


## Network Exploitation

### DNS-over-HTTPS Bypass  `doh_bypass`  _[original]_

- **Scope:** attack_sim/B · direction a2b · ports — (no target port; egress / ICMP) · MITRE T1572 · CWE-693
- **What it tests / why:** DNS-over-HTTPS bypass check. Unlike the other modules, this doesn't attack the lab target at all — it tests whether the perimeter appliance's DNS filtering can be bypassed by tunnelling DNS over HTTPS (port 443) to a public DoH resolver, matching the manual test script exactly.
- **Control it validates (how to PREVENT / BLOCK):** DNS filtering / egress control
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** tools: curl

### FTP Anonymous Login  `ftp_anonymous`  _[original]_

- **Scope:** va · direction a2b · ports 21/tcp · MITRE T1078.001 · CWE-306
- **What it tests / why:** FTP anonymous login check. Matches the manual test script's curl test, with -v added so a real FTP "230 Login successful" is visible even when the directory listing itself is empty (empty stdout would otherwise look identical to a rejected login).
- **Control it validates (how to PREVENT / BLOCK):** Anonymous access hardening
- **Fix (owner / remediation):** Server
- **Needs to run:** tools: curl

### ICMP Flood (DoS)  `icmp_flood`  _[original]_

- **Scope:** dos · direction a2b · ports icmp · MITRE T1498.001 · CWE-400
- **What it tests / why:** ICMP Flood (DoS) — tests ICMP rate-limit / flood protection at the boundary.
- **Control it validates (how to PREVENT / BLOCK):** ICMP rate-limit / flood (DoS) protection
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** tools: ping; **root**

### SNMP Community Brute  `snmp_brute`  _[original]_

- **Scope:** va · direction a2b · ports 161/udp · MITRE T1110.001 · CWE-1392
- **What it tests / why:** SNMP community string brute force. Walks wordlists/snmp_communities.txt (falls back to just 'public' if that file is missing), stopping at the first community that gets real MIB data back — 'public' is deliberately LAST in that wordlist: it's the one the old single-check version of this module always tried, so landing on anything else FIRST is the more interesting finding (a non-default string someone picked is still a guessable one), and 'public' working is the unsurprising baseline case.
- **Control it validates (how to PREVENT / BLOCK):** Default-credential / community-string hygiene
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** tools: snmpbulkwalk

### SSH Brute Force  `ssh_brute`  _[original]_

- **Scope:** va · direction a2b · ports 22/tcp · MITRE T1110.001 · CWE-307
- **What it tests / why:** SSH brute-force — tests the boundary's brute-force protection by generating a rapid burst of SSH **connection attempts** (not a single check), then verifying whether a valid credential still gets through.
- **Control it validates (how to PREVENT / BLOCK):** Brute-force protection / rate-limit (SSH)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** tools: hydra; SSH creds

### External DNS Egress (UDP/53 to public resolver)  `dns_egress_external`  _[added]_

- **Scope:** attack_sim/B · direction a2b · ports 53/udp · MITRE T1071.004, T1048.001 · CWE-693
- **What it tests / why:** Family B — direct plaintext DNS (UDP/53) to an EXTERNAL resolver.
- **Control it validates (how to PREVENT / BLOCK):** Restrict outbound 53 to internal resolvers only
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** config.json: external_resolver

### DNS Tunnelling (iodine/dnscat2)  `dns_tunnel`  _[added]_

- **Scope:** attack_sim/B · direction a2b · ports — (no target port; egress / ICMP) · MITRE T1071.004, T1048.001 · CWE-693
- **What it tests / why:** Family B — classic DNS tunnelling to an attacker authoritative NS.
- **Control it validates (how to PREVENT / BLOCK):** Restrict/monitor recursive DNS; block new authoritative zones
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** **--active** (live establishment); config.json: attacker_domain, canary_dns_zone, external_resolver

### DNS-over-HTTPS Bypass (multi-resolver + attacker DoH)  `doh_multi`  _[added]_

- **Scope:** attack_sim/B · direction a2b · ports — (no target port; egress / ICMP) · MITRE T1071.004, T1572 · CWE-693
- **What it tests / why:** Family B — DNS-over-HTTPS bypass across multiple resolvers (+ attacker DoH).
- **Control it validates (how to PREVENT / BLOCK):** Forced internal resolver / DoH blocking (443)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** tools: curl; config.json: attacker_doh, doh_providers

### DoT/DoQ Egress (853)  `dot_doq_853`  _[added]_

- **Scope:** attack_sim/B · direction a2b · ports 853/tcp, 853/udp · MITRE T1071.004 · CWE-693
- **What it tests / why:** Family B — DNS-over-TLS (TCP/853) and DNS-over-QUIC (UDP/853) egress.
- **Control it validates (how to PREVENT / BLOCK):** Default-deny egress ports (853 not permitted outbound)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** config.json: attacker_vps

### SYN Flood (DoS)  `syn_flood`  _[added]_

- **Scope:** dos · direction a2b · ports 80/tcp · MITRE T1498.001 · CWE-400
- **What it tests / why:** SYN Flood (DoS) — tests TCP SYN-flood rate-limit / DoS protection at the boundary.
- **Control it validates (how to PREVENT / BLOCK):** SYN-flood rate-limit / DoS protection
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** tools: hping3, timeout; **root**


## Segmentation

### East-West Lateral (WMI/WinRM/RDP/SMB)  `eastwest_lateral`  _[added]_

- **Scope:** attack_sim/D · direction both · ports 445/tcp, 5985/tcp, 135/tcp, 3389/tcp · MITRE T1021.002, T1047, T1021.006
- **What it tests / why:** Family D — east-west lateral movement (WMI / WinRM / RDP / SMB).
- **Control it validates (how to PREVENT / BLOCK):** Host firewalls between servers; EDR blocks remote-exec; tiered admin
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** **--active** (live establishment)

### IPv6 ACL Parity Sweep  `ipv6_acl_parity`  _[added]_

- **Scope:** attack_sim/D · direction a2b · ports — (no target port; egress / ICMP) · MITRE T1599, T1046 · CWE-923
- **What it tests / why:** Family D — IPv6 ACL parity.
- **Control it validates (how to PREVENT / BLOCK):** IPv6 ACLs mirror IPv4 (deny by default on both stacks)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** nothing (just a reachable target)

### NMAP Port-Policy Violation Scan (IPS-bypass)  `nmap_policy_scan`  _[added]_

- **Scope:** attack_sim/D · direction a2b · ports — (no target port; egress / ICMP) · MITRE T1046, T1595.001 · CWE-923
- **What it tests / why:** NMAP Port-Policy Violation Scan (IPS-bypass).
- **Control it validates (how to PREVENT / BLOCK):** Allowed-port policy enforcement + port-scan IPS (App-ID / NGFW)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** tools: nmap; **root**

### Reverse / Server-initiated Egress (B->A/out)  `reverse_egress`  _[added]_

- **Scope:** attack_sim/D · direction b2a · ports — (no target port; egress / ICMP) · MITRE T1571, T1090 · CWE-923
- **What it tests / why:** Family D — reverse / server-initiated egress (B -> A / B -> out).
- **Control it validates (how to PREVENT / BLOCK):** Default-deny server-initiated egress (DC VLAN)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** config.json: attacker_vps

### Segmentation Sweep (mgmt/DB/lateral ports)  `segmentation_sweep`  _[added]_

- **Scope:** attack_sim/D · direction a2b · ports — (no target port; egress / ICMP) · MITRE T1046 · CWE-923
- **What it tests / why:** Segmentation sweep (A -> B). Checks a broad set of sensitive management / database / lateral-movement ports and reports which are reachable through the SD-WAN. Every reachable port is a segmentation gap the policy permits — the #1 question for an agency-to-KVDC/cloud SD-WAN. Pure sockets: no external tools, no root, runs on any OS. Advisory recon is separate; this module IS the check, so its own output is the evidence.
- **Control it validates (how to PREVENT / BLOCK):** Network segmentation / firewall policy (A->B)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** nothing (just a reachable target)

### 443 SOCKS Pivot to Segmented Service  `socks_pivot`  _[added]_

- **Scope:** attack_sim/D · direction a2b · ports — (no target port; egress / ICMP) · MITRE T1572, T1021 · CWE-923
- **What it tests / why:** Family D — 443 SOCKS pivot to a segmented service (impact proof).
- **Control it validates (how to PREVENT / BLOCK):** App-ID on 443 (HTTP only) + micro-segmentation independent of egress
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** **--active** (live establishment); config.json: attacker_vps, internal_pivot_target

### Stateful-inspection Evasion (frag / src-port)  `stateful_evasion`  _[added]_

- **Scope:** attack_sim/D · direction a2b · ports — (no target port; egress / ICMP) · MITRE T1205 · CWE-923
- **What it tests / why:** Family D — stateful-inspection evasion (fragmentation + source-port trust).
- **Control it validates (how to PREVENT / BLOCK):** Reassembly-aware inspection; no trust of source port; anti-spoofing
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** tools: hping3; **root**

### Switch/Router Mgmt-plane Exposure  `switch_mgmt`  _[added]_

- **Scope:** attack_sim/D · direction both · ports — (no target port; egress / ICMP) · MITRE T1046, T1078 · CWE-923
- **What it tests / why:** Family D — network-device (switch/router) management-plane exposure.
- **Control it validates (how to PREVENT / BLOCK):** No device management reachable across zones (mgmt VRF isolated)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** config.json: switch_targets


## Server Exploitation

### Apache Path Traversal (CVE-2021-41773)  `apache_41773`  _[original]_

- **Scope:** pentest · direction a2b · ports 80/tcp · MITRE T1190 · CWE-22 · CVE-2021-41773
- **What it tests / why:** CVE-2021-41773 — Apache path traversal (mod_cgi normalize-path bug). Direct HTTP check (curl): request /cgi-bin/.%2e/.. x7 to escape docroot and read a sensitive file. Tries BOTH a Linux target (/etc/passwd) and a Windows target (/windows/win.ini) — the vulnerable file differs by OS, and the lab's Apache container is Linux, so a win.ini-only check 404s against its own lab.
- **Control it validates (how to PREVENT / BLOCK):** IPS signature / path normalization
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** tools: curl

### Log4Shell (CVE-2021-44228)  `log4shell`  _[original]_

- **Scope:** pentest · direction a2b · ports 8080/tcp · MITRE T1190 · CWE-917 · CVE-2021-44228
- **What it tests / why:** CVE-2021-44228 — Log4Shell. Sends a BENIGN JNDI marker string in the User-Agent and a header so the SD-WAN IPS's JNDI signature is actually exercised (not just a reachability ping), against /solr/ — Apache Solr's real admin/API surface, not '/' (which just redirects there unconditionally on this target and proves nothing about the payload itself).
- **Control it validates (how to PREVENT / BLOCK):** IPS signature (JNDI pattern)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** tools: curl

### Struts2 OGNL Injection (CVE-2017-5638)  `struts2_ognl`  _[added]_

- **Scope:** pentest · direction a2b · ports 80/tcp · MITRE T1190 · CWE-917 · CVE-2017-5638
- **What it tests / why:** Struts2 OGNL injection (CVE-2017-5638) — ZERO-config IPS/WAF signature test.
- **Control it validates (how to PREVENT / BLOCK):** IPS/WAF signature (Struts2 OGNL / Content-Type)
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** tools: curl

### Web IPS/WAF Signature Battery  `web_ips_sigs`  _[added]_

- **Scope:** attack_sim/D · direction a2b · ports 80/tcp · MITRE T1190, T1059 · CWE-89, CWE-79, CWE-78, CWE-22
- **What it tests / why:** Web IPS/WAF signature battery — ZERO-config IPS-practice check.
- **Control it validates (how to PREVENT / BLOCK):** IPS/WAF web-attack signatures
- **Fix (owner / remediation):** SD-WAN
- **Needs to run:** tools: curl

