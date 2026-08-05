# Use-Case Focus, Honest Crypto Variation & UI Redesign

> Answers three questions before we resume building:
> 1. **Is there a single, concrete use-case to focus the whole project (and UI) around** so it's
>    convincing to an evaluator? — **Yes. §1–§2.**
> 2. **Can I honestly include *varying* crypto levels** without reintroducing the category error
>    the whole redesign was meant to kill? — **Yes, along the *assurance* axis, not the threat
>    axis. §3.**
> 3. **The UI is unappealing and disjointed — how do we fix it?** — **A single narrative console
>    built around the use-case. §4–§6.**
>
> This sits on top of `PROJECT_REDESIGN.md` (R1–R4) and `FINAL_PROTOTYPE.md`; it does not replace
> them — it gives them a *story* and a *face*.

---

## 1. Why a use-case matters (the problem with the current pitch)

Right now the project is pitched as a *capability list*: "PQC + SCTP + ML in one gateway." An
evaluator hears three buzzwords and asks the killer question: **"Why these three together? Why
SCTP and not just TLS 1.3 with a PQC group?"** Today there's no crisp answer, because the demo is
a *feature tour* (six disconnected beats) rather than *one actor solving one problem*.

The fix is to pick a **vertical where all three technologies are individually forced by the
domain** — so their co-existence stops looking like a science-fair mashup and starts looking
inevitable. The best such vertical is one where **SCTP is the native transport**, because that is
the single weakest link in the current story.

---

## 2. The recommended use-case

### 2.1 Headline (recommended): **Post-Quantum Resilience Gateway for critical signaling links**

> *A drop-in gateway that upgrades a legacy plaintext-TCP control link — telecom core signaling
> (Diameter/SS7-over-SIGTRAN), grid/SCADA telemetry, or interbank messaging — into an
> **authenticated, hybrid post-quantum, multihomed SCTP association**, kept alive and watched by
> ML, without touching the legacy endpoint.*

Why this vertical makes every leg **non-arbitrary** — each answers an evaluator objection:

| Leg | The objection it silences | Why the vertical forces it |
|---|---|---|
| **SCTP** | *"Why not TLS-over-TCP?"* | The telecom **signaling plane already runs on SCTP** (SIGTRAN, Diameter). Multihoming is a **carrier-grade 99.999% availability requirement**, not a gimmick. You're hardening the transport the domain *already uses*. |
| **PQC** | *"Why post-quantum today? Nobody has a quantum computer."* | Signaling carries **decades-lived secrets** — subscriber identifiers, session metadata, keys, financial instructions. **Harvest-now-decrypt-later** is a documented nation-state concern for exactly this traffic. Long confidentiality lifetime ⇒ PQC is justified *now*. |
| **ML (transport)** | *"Why does availability need ML?"* | These links have **hard SLAs**; a reactive failover that waits for a dead path loses messages. ML that reads network condition and fails over **proactively** (before the SLA breach) is a real operational win. |
| **ML (threat)** | *"Isn't a firewall enough?"* | The signaling plane has its **own attack surface** (SS7/Diameter floods, signaling storms). A detector on the *upgraded* link flags those and drives rate-limit/quarantine — an availability response, not a crypto one. |

The concrete demo actor (pick one you're comfortable narrating): **"a hospital's patient-record
uplink"**, **"a bank's payment-messaging link"**, or **"a mobile operator's signaling gateway."**
All three share the same two properties that justify the stack: *data with a long confidentiality
lifetime* + *an availability SLA*. Tell it as one actor's story end-to-end.

### 2.2 Two safer alternatives (if telecom feels too niche for your evaluator)

- **B — Secure remote-site uplink (SD-WAN-flavoured).** A branch office / field device with **two
  uplinks** (fibre + LTE) needs a quantum-safe tunnel to HQ that survives a link drop. Most
  *relatable* to a general audience; multihoming maps to "two ISPs." Slightly weaker on "why SCTP"
  (an evaluator could say "use MPTCP/WireGuard").
- **C — Industrial / OT or medical-device gateway.** A legacy OT device you **cannot modify or
  re-certify**; the gateway bolts on quantum-safe + resilient transport transparently. Strongest
  "you can't touch the endpoint" and "data lifetime is 20+ years" story; multihoming is real
  (redundant plant networks) but less native than telecom.

**Recommendation:** lead with **A** for coherence (it's the only one where SCTP is *native*), but
frame the opening line so it generalises: *"critical links that need both long-term confidentiality
and carrier-grade availability — telecom signaling, grid control, financial messaging."* That one
sentence lets you pivot to whichever example your evaluator relates to.

> **Nothing in the code changes for this.** The use-case is a **framing + UI + narration** layer
> over the exact system in `FINAL_PROTOTYPE.md`. "Legacy TCP in → authenticated PQC SCTP out" is
> already what the gateway does; we're just naming *who* the legacy endpoint is and *why they care*.

---

## 3. Honest crypto-level variation — the assurance axis

You asked whether you can still *vary* the crypto level. **Yes — and it becomes a feature, not a
liability — if it varies along the right axis.** The original sin was varying crypto by **ML threat
level** (a DDoS doesn't make a key breakable). We keep that dead. But there are legitimate axes:

### 3.1 The rule that keeps it honest

> **Crypto strength may scale with the *value / confidentiality-lifetime of the data* (the
> assurance axis, set by policy), and may only ever move *UP* from the floor. It never scales with
> network/threat conditions, and nothing can move it *DOWN* below the floor.**

This is not only defensible — it's *correct security engineering*. Crypto strength **should** track
how long the data must stay secret and how sensitive it is. That's a **policy attribute of the
channel**, completely independent of the ML detector. Three concrete, legitimate drivers you can
demo (all monotonic-up-from-floor):

| Driver (assurance axis) | Example | Effect |
|---|---|---|
| **Data classification** | ROUTINE telemetry vs SENSITIVE subscriber data vs CRITICAL keying material | ROUTINE → ML-KEM-768 (floor); CRITICAL → ML-KEM-1024 |
| **Compliance / regulatory mode** | "CNSA 2.0 mode" or a customer contract mandating Level-5 | forces ML-KEM-1024 regardless of anything else |
| **Peer-negotiated capability** | the level is `max(both endpoints support)`, floored | real handshake negotiation, not a slider |

You already have the mechanism: the `high_assurance` posture in `crypto_policy` raises the KEM to
ML-KEM-1024. We simply **rename and reframe** it from a vague toggle into a **"Data Assurance
Tier" / "Classification"** selector, and draw the **floor as an immovable line** underneath it.

### 3.2 Why this makes the demo *stronger*

It turns the floor beat (your headline) into a **two-directional proof**:

```
        ML-KEM-1024  ┌───────────────── assurance/compliance may RAISE ▲
                     │        (policy-driven, data-value-driven)
   FLOOR ML-KEM-768  ├━━━━━━━━━━━━━━━━━━  ← immovable line
                     │        battery / threat / load may NOT lower ✗
        ML-KEM-512   └───────────────── (never reachable — below floor)
```

- Drag **Data Classification → CRITICAL**: KEM rises 768 → **1024** (legitimate, up).
- Drag **Battery pressure → 100%**: KEM **stays 768** (attacker's downgrade blocked).
- Flip **Threat → HIGH**: KEM **does not move** (category error stays dead); only the *transport*
  axis reacts.

That's three sliders, one immovable red line, and a single sentence: **"the only thing that can
change crypto strength is a policy decision about the data's value, and it can only go up."** It
directly answers "can I vary crypto?" *and* showcases the contribution.

> ⚠️ **The one thing never to do:** wire the ML detector (or battery) to the crypto selector. The
> assurance selector must be **manual/policy input**, visibly on the *other side* of the wall from
> ML. If ML ever touches it, you're back to the category error.

---

## 4. UI redesign — from feature-tour to one operations console

### 4.1 What's wrong today

- **Six disconnected pages** (`1_live_monitor` … `8_demo_scenarios`) = a feature tour, not a story.
- **Stale framing** — some pages still imply "Kyber scales with threat" (the thing you fixed).
- **Dead weight** — `3_analyst_chat` (LLM, parked) and `4_threat_narrative` (old LLM framing)
  contradict the current design and are demo liabilities.
- **Generic Streamlit look** — default theme, no topology, no visual identity; nothing *shows* the
  two-axis idea that is the whole point.

### 4.2 The redesign principle: **a mission-control console for one link**

One screen that always shows **the link and its live state**, with the two axes rendered as two
visibly separate columns that *never cross*. The evaluator should grasp the architecture from the
layout alone, before you say a word.

```
 ┌───────────────────────────────────────────────────────────────────────────┐
 │  ⬢ POST-QUANTUM RESILIENCE GATEWAY  ·  <use-case name>       ● LIVE  self-test✔│  ← header/identity
 ├───────────────────────────────────────────────────────────────────────────┤
 │  HERO: LINK TOPOLOGY (animated)                                            │
 │   legacy TCP ─►[GATEWAY]═══ PATH-1 (fibre)  ●active ══►[RECEIVER]          │
 │                    🔒          ╲ PATH-2 (LTE) ○standby ╱                   │
 │        auth: ML-DSA-65 ✔     KEM: ML-KEM-768 🔒floor    AES-256-GCM        │
 ├──────────────────────────────────┬────────────────────────────────────────┤
 │  CRYPTO axis (confidentiality)    │  TRANSPORT axis (availability)         │
 │  ── set by POLICY, up-only ──     │  ── set by ML, never touches crypto ── │
 │  Assurance tier:  [ROUTINE▸CRIT]  │  Network condition (ML-A): STABLE      │
 │  Resulting KEM:   ML-KEM-768      │  SCTP action: NORMAL / FAILOVER        │
 │  ▓▓▓ floor line (immovable) ▓▓▓   │  Threat (ML-B):  LOW → RATE_LIMIT      │
 │  battery:100% → still 768 ✅       │  active path, failover events table    │
 ├──────────────────────────────────┴────────────────────────────────────────┤
 │  EVIDENCE strip:  [Run self-test]  KEM=0.05ms/handshake  macro-F1 0.87      │
 └───────────────────────────────────────────────────────────────────────────┘
```

The **wall between the two columns is the design.** Left = crypto, moved only by the policy slider,
floored. Right = ML → transport. They are drawn as physically separate so the "they never cross"
claim is *visible*, not just spoken.

### 4.3 Page map — consolidate 6 → 4, aligned to the demo beats

| New page | Absorbs | Purpose (beat) |
|---|---|---|
| **1 · Command Console** (the hero above) | `1_live_monitor` | the always-on link + two-axis view (beats 1–4) |
| **2 · Scenario Control** | `2_simulation`, `8_demo_scenarios` | drive Normal/DDoS/Congestion + posture + assurance tier + path cut (beats 2,3,4,5) |
| **3 · PQC & Trust** | `5_pqc_visualizer` | handshake decomposition, size fingerprint, **ML-DSA auth + MitM-blocked** demo, self-test button (beat 6a, PQC_VALIDATION) |
| **4 · Evidence** | `4_threat_narrative` (repurposed) | confusion matrix, macro-F1, honest limitations, event log (beat 6b) |
| ~~`3_analyst_chat`~~ | **delete/hide** | LLM is parked; it contradicts the current story |

### 4.4 Visual overhaul within Streamlit (low-risk, keeps the working engine)

Streamlit stays the live engine (it already talks to `metrics.db`, the posture file, and the
gateway log). We make it *look* like a product:

1. **A theme** — `ai_module/dashboard/.streamlit/config.toml` with a dark ops-console palette
   (one accent for "secure/up", one for "alert"), a mono font for the log, consistent spacing.
2. **A shared component library** — one `ui.py` with `axis_card()`, `status_pill()`, `kem_meter()`,
   `topology()` so every page looks the same instead of ad-hoc `st.metric` calls.
3. **An SVG/HTML topology hero** — a small inline SVG (via `st.components.v1.html`) with the active
   path highlighted and a padlock that reflects live KEM + auth state. This is the single biggest
   "looks real" upgrade.
4. **The two-axis layout** as two `st.columns` with a drawn divider and the floor line rendered as
   a fixed horizontal rule in the KEM meter.
5. **Kill stale copy** — every "Kyber scales with threat" string replaced with the floor framing.

> **Optional high-polish backup:** a **single self-contained HTML page** (publishable as an
> Artifact) that mirrors the console for the *opening slide* / screen-record backup. It's static
> but pixel-perfect and never breaks live — the ideal thing to show first and to fall back to if
> Streamlit hiccups. Recommended *after* the Streamlit overhaul lands, not instead of it.

---

## 5. How this threads back into R1–R4 (build order)

This plan reprioritises the redesign work so every step ends in something **visible on the console**:

1. **Finish R1 (ML-DSA authentication)** — already in progress. Payoff: the **auth ✔ indicator**
   on the hero + a **"MitM blocked"** micro-demo (tamper a key → handshake aborts) on *PQC & Trust*.
   This finally lets you claim authentication honestly.
2. **Assurance-tier crypto control (§3)** — rename `high_assurance` → data-classification tier,
   wire the up-only KEM meter with the immovable floor line. Small change, huge demo value.
3. **R2 + R3 (ML-A network condition → SCTP policy)** — even minimal (STABLE/CONGESTED/PRE_FAILURE
   → proactive failover) lights up the **right-hand transport column** with a real second ML model.
4. **R4 = the UI overhaul (§4.3–§4.4)** — build the console, consolidate pages, apply the theme,
   delete the dead LLM pages.
5. **(Optional) the HTML Artifact backup (§4.4).**

Each step is independently demoable, so you're never mid-refactor with nothing to show.

---

## 6. What changes vs. what stays (so scope is clear)

- **Stays exactly as built:** the C gateway, hybrid handshake, SCTP relay, CIC detector, floor
  invariant, `run_demo.sh`. No architectural rework.
- **New (small):** data-classification framing of the assurance posture; ML-A minimal model + SCTP
  policy wiring (already R2/R3); finishing ML-DSA auth (already R1).
- **New (UI):** the console layout, theme, topology hero, page consolidation, dead-page removal.
- **Framing only:** naming the use-case actor and re-narrating the demo around one link's lifecycle
  (update `EVALUATOR_SCRIPT.md` §0 opening + tie each beat to the actor).

---

## 7. Open decision for you

Pick the **vertical** to anchor the narration and UI copy (the code is identical either way):

- **A — Telecom / critical signaling** *(recommended: SCTP is native, silences "why not TLS")*
- **B — Secure remote-site dual-uplink** *(most relatable to a general evaluator)*
- **C — Industrial/OT or medical-device gateway** *(strongest "can't touch the endpoint" + data
  lifetime story)*

Tell me which (or "A but narrate it as a hospital/bank/operator") and whether to include the
**assurance-tier crypto variation (§3)** as a demo beat, and I'll start on the build order in §5 —
beginning by finishing R1, then the assurance control, then the console.
```
