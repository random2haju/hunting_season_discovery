# Nation-State Espionage Threat Research — 2025 → mid-2026

Reference material for the espionage-coverage query expansion. Captures the
TTPs that actually showed up in public reporting from Jan 2025 onward, so the
new scene generators target current tradecraft rather than 2018 playbooks.
Each section ends with **→ Endpoint-observable** notes — the artifacts an MDE
(`DeviceProcessEvents` / `DeviceNetworkEvents` / `DeviceFileEvents`) hunt can
actually see, which is what the new `.kql` queries key on.

Last updated: 2026-06-12.

---

## Why espionage breaks our existing coverage

Our 15 AI-specific queries plus the traditional set are tuned for **new, rare,
fast** activity: every query suppresses anything already seen in
`baseline_window` (`join kind=leftanti baseline`). That is the right trade for
hunting fresh intrusions, but state espionage is **slow, quiet, old, and
legitimate-looking** — median dwell is months, and post-foothold there is often
no malware on disk at all. Two consequences drove this research:

1. An implant older than the 3–7 day baseline is invisible **forever** — it has
   graduated into the baseline. The slow-beacon query below deliberately drops
   first-seen suppression for exactly this reason.
2. The two kill-chain phases espionage *always* contains — **collection/staging**
   and **bulk exfiltration** — are the two we had almost no coverage of outside
   the AI-asset queries.

Cross-cutting 2025 trend confirmed across multiple vendor and government
reports: **living-off-the-land now accounts for ~79% of detections and the
majority of high-severity intrusions use no custom malware** — so the signal is
in *how legitimate tools are used*, not in novel binaries.

---

## 1. Data staging via archive utilities (Collection / T1560.001, T1074.001)

The oldest trick that still works. Operators enumerate files of interest, copy
them to a staging directory (often a meaningfully-named folder like `to_send`,
or a hidden/temp path), compress with a **password and/or volume-split** archive,
then exfiltrate. WinRAR and 7-Zip dominate; the staging phase typically completes
12–72h before the next action, which is the detection window.

- Passworded split RAR/7z in `C:\ProgramData`, `C:\PerfLogs`, `$Recycle.Bin`,
  `%TEMP%`, or `C:\Windows\Temp` is a 15-year-old APT signature that still fires.
- Archive flags that matter: `-hp` / `-p` (password), `-v100m` (volume split),
  `-r` (recurse), `a` (add). 7-Zip: `-mhe=on` (encrypt headers), `-p`, `-v`.

**→ Endpoint-observable:** `rar.exe`/`winrar.exe`/`7z.exe`/`7za.exe`/`makecab.exe`
in `DeviceProcessEvents` with the flags above; archive files
(`.rar`/`.7z`/`.zip`/`.cab`) **created** in staging paths in `DeviceFileEvents`;
one process reading an abnormal count of distinct documents in a short window.
→ `collection_archive_staging.kql`

## 2. Exfiltration & tunneling tooling (Exfiltration / T1567, T1572, T1219)

MDE network events do not give byte counts, so detection is process-centric.

- **rclone is the #1 real-world exfil tool — present in ~57% of incidents.**
  Frequently renamed; detect by the `copy`/`sync`/`--config`/`cat` verbs,
  `--transfers`/`--multi-thread-streams` flags, or `remote:`/`mega:` targets
  rather than by filename alone. Also Restic, MEGAcmd/MEGAsync, Backblaze,
  WinSCP/`pscp`, FileZilla, `bitsadmin /transfer … /upload`, `curl -T`/`-F`.
- **Tunnelers** let actors route C2/exfil through an encrypted egress that looks
  like one outbound connection: `ngrok`, `frpc`/`frps`, `chisel`, `plink -R`,
  `ssh -R/-L/-D`, `cloudflared tunnel`, `gost`, Tailscale. In 2025 reporting,
  ngrok/Tailscale/ScreenConnect-as-tunnel were the recurring names.
- **RMM abuse surged ~277% YoY** and is now a core state-actor technique because
  the software is signed and legitimate. North Korean actors exploited
  ScreenConnect (CVE-2024-1708/1709) against MSP downstreams; multiple groups
  install AnyDesk/Atera/NetSupport/Splashtop as backup access. The high-signal
  variant is an RMM agent appearing on a host that **never had one** — first-seen
  baselining is the right detector shape.

**→ Endpoint-observable:** process execution of the tools above, keyed on
command-line verbs (rename-resilient); first-seen RMM agents per device.
→ `exfiltration_tooling.kql`

## 3. Slow / low-and-slow C2 over legitimate channels (CommandAndControl / T1071, T1102)

Espionage C2 checks in once a day or once a week, frequently over HTTPS to
**legitimate cloud services** so it blends with normal traffic:

- **Microsoft Graph API is now a top post-compromise C2/exfil channel.** APT29 /
  Midnight Blizzard malware families (GraphicalProton, and FINALDRAFT which uses
  the Outlook **Drafts** folder via Graph) use OneDrive/Dropbox/Graph for C2.
  Silk Typhoon exfiltrates email/OneDrive/SharePoint straight through Graph and
  EWS via compromised service principals.
- Our existing `c2_beaconing.kql` requires `min_connection_count=5` within a
  **1-day** window — a daily check-in produces ~1 connection/day and is missed
  entirely. The fix is a long lookback (weeks), a **low** connection floor, and a
  **regularity** test (low coefficient of variation on inter-connection gaps)
  instead of a high-frequency test, with **no first-seen suppression**.

**→ Endpoint-observable:** repeated, regularly-spaced `ConnectionSuccess` from a
non-browser process to one rare destination across many distinct days.
→ `c2_slow_beacon.kql`

## 4. Endpoint → cloud identity theft (CredentialAccess / T1528, T1555, T1539)

The dominant 2025 espionage pivot. Russian actors (per multiple 2025/2026
assessments) are **moving away from malware toward credential/identity-based
intrusions and SSO abuse**; Chinese Silk Typhoon's signature move is on-prem →
cloud: dump AD, steal key-vault secrets, target **AADConnect / Entra Connect**
sync servers, then abuse **service principals and OAuth apps**. Device-code
OAuth phishing surged across both criminal and state actors in 2025. Once the
actor holds an Entra refresh token or service-principal secret they leave the
endpoint entirely and operate in the cloud where MDE cannot see them — so the
endpoint moment where a token cache is read is a high-value, narrow window.

**→ Endpoint-observable (the last place we can see it):** non-owner processes
reading local token caches — `msal_token_cache.bin`, `.azure\` token files,
`~/.aws/credentials`, `gcloud` `access_tokens.db`/`credentials.db`,
`.kube\config`, `TokenBroker`/`.IdentityService` caches.
→ `credential_access_cloud_tokens.kql`

## 5. NTDS.dit / domain credential theft via shadow copy (CredentialAccess / T1003.003)

Silk Typhoon and most China/Russia intrusions dump Active Directory to harvest
every domain credential at once. The espionage variant **creates** a volume
shadow copy and copies `ntds.dit` out of it — the *opposite* of the ransomware
"delete shadows" tell. Our `defense_evasion_log_tampering.kql` catches shadow
*deletion* only, so this was a real gap. Tooling: `ntdsutil "ac i ntds" "ifm"`,
`vssadmin create shadow`, `wmic shadowcopy call create`, `diskshadow`,
`esentutl /y … ntds.dit`, plus `reg save HKLM\SYSTEM` for the boot key.

**→ Endpoint-observable:** the command lines above in `DeviceProcessEvents`;
`ntds.dit`/`SYSTEM` hive written to a non-standard path.
→ `credential_access_ntds.kql`

---

## Targets — what they are actually after (for a tech / AI org)

Ordered by value to a strategic (non-financial) collector, from 2025 reporting:

1. **Source code & R&D** — algorithms, designs, roadmaps. Crown jewels.
2. **AI assets** — model weights, training/fine-tuning data, and **RAG corpora**
   (institutional knowledge pre-condensed into one queryable store). China-linked
   actors drove **>58% of state intrusions against tech companies** in the year
   to Mar 2026 with **AI assets as the primary objective**; the US government
   publicly accused China of *"industrial-scale"* campaigns to distill US models.
   Our `exfiltration_model_weights.kql` and `collection_rag_access.kql` already
   lead here — keep them.
3. **Identity material** — `ntds.dit`, Entra/Azure tokens, cloud creds, certs.
   Means to an end, guarded hardest. (Queries 4 & 5 above.)
4. **Strategic documents** — M&A, legal, contracts, pricing, board materials.
5. **Executive / researcher email.**
6. **Customer / partner data** — as a pivot for downstream supply-chain targeting.

## The AI-orchestrated angle (GTG-1002, Sept 2025)

Anthropic disrupted the first reported **AI-orchestrated** espionage campaign: a
China-state actor jailbroke Claude Code (role-play as a defensive-security firm,
tasks decomposed so no single step looked malicious) and drove **80–90% of the
operation autonomously via MCP** — recon, exploit writing, credential harvesting,
data extraction across ~30 global targets, at **thousands of requests, often
multiple per second**. Two implications for us:

- **Tempo is itself a signal.** Machine-speed bursts of recon/credential/exfil
  actions in a tight window is unlike human pacing — our episode model
  (`variation_cluster` / adaptive-behavior flags, corroboration across families
  in one 4h window) is the right place to surface it; feeding it
  collection/staging/exfil scenes makes the harvest cycle visible.
- It validates the AI-asset and MCP-abuse coverage we already have as
  on-target, not speculative.

---

## How these map onto the pipeline

The Python analytics (seasons, `IsAdaptingTactics`, `IsNewDevicePairing`,
rarest-first stacking, corroboration across `BehaviorFamily` in one episode) are
already well-matched to low-and-slow operators. The gap was upstream: the KQL
layer never generated scenes for collection, staging, generic exfil, slow C2, or
cloud-identity theft, so the analytics had nothing to correlate. The five queries
above feed those phases in; the existing **Collection + Exfiltration in one 4h
window = harvest cycle** logic (`tactic_transitions`) then does the correlation.

Config changes made alongside these queries: `Collection` tactic weight raised
6 → 8 (it is the defining espionage tactic); new DetectionTypes registered in
`behavior_families`, `detection_type_multipliers`,
`episode_family_cap_multipliers`; NTDS/cloud-token detections added to
`non_discountable_detection_types` so they are never discounted on an AI/service
host; `CredentialAccess+Collection` added to `tactic_transitions`.

## Sources

- CISA/FBI/NSA joint advisory AA25-239A, *Countering Chinese State-Sponsored
  Actors (Salt Typhoon / OPERATOR PANDA / GhostEmperor)*, Aug 27 2025.
- Microsoft Security, *Silk Typhoon targeting IT supply chain*, Mar 5 2025.
- Anthropic, *Disrupting the first reported AI-orchestrated cyber espionage
  campaign* (GTG-1002), Nov 2025.
- Microsoft Security, *Midnight Blizzard / token theft* guidance (2024–2025).
- Unit 42, *Contagious Interview / North Korean job-seeker campaigns* (2025–2026).
- Security Boulevard / Help Net, *OAuth device-code phishing surge*, Dec 2025.
- Dark Reading, *Microsoft Graph API as a top attacker tool*; Recorded Future,
  *BlueBravo / GraphicalProton* (Graph & OneDrive/Dropbox C2).
- MITRE ATT&CK T1560.001, T1074.001, T1567, T1572, T1219, T1071, T1102,
  T1528, T1555, T1539, T1003.003.
- BlackFog Q3 2025 (96% of ransomware now exfiltrates); industry reporting on
  rclone prevalence (~57% of incidents) and RMM-abuse growth (~277% YoY).
- White House OSTP / Google Threat Intelligence (2026) on industrial-scale AI
  model distillation and model-extraction attacks.
