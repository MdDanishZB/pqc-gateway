# Intelligent Secure Gateway: Post-Quantum Cryptography and Machine-Learning-Driven Network Resilience for Legacy TCP Systems

---

## Abstract

Legacy TCP-based systems in critical infrastructure, industrial control, and enterprise
environments continue to rely on classical cryptographic primitives that are vulnerable to
large-scale quantum computation and offer no adaptive response to network degradation. This
project presents an **Intelligent Secure Gateway** that transparently upgrades legacy TCP
traffic into an authenticated, hybrid post-quantum SCTP tunnel while introducing two
independently trained machine-learning models to govern distinct operational concerns. A
**Security Policy Engine** determines cryptographic strength exclusively from the declared
sensitivity of the data being transmitted, enforcing a fixed minimum security level
(hybrid X25519 + ML-KEM-768) that can only be raised — never lowered — for data classified as
critical. Independently, a **network-condition classifier** analyzes live path-health metrics
(round-trip time, jitter, packet loss, throughput, and congestion window) to categorize the
transport path into one of five operational states and issues corresponding SCTP transport
policy recommendations, including proactive failover across a multihomed association. A
separate **threat-detection classifier**, trained on the CIC-IDS2017 intrusion-detection
dataset, evaluates traffic-flow statistics to identify anomalous or malicious behavior and
triggers rate-limiting and alerting responses. Session keys are derived via HKDF-SHA-256 over
the combined classical and post-quantum shared secrets and used for AES-256-GCM authenticated
encryption. The system further incorporates ML-DSA-65 digital signatures to authenticate the
key-exchange transcript, preventing man-in-the-middle substitution. The complete system was
implemented in C (gateway core, cryptographic handshake, SCTP transport) and Python
(machine-learning inference and observability), and validated through unit testing, cryptographic
self-tests conforming to FIPS 203 and FIPS 204 parameter specifications, and failover
measurement over a dual-path network-namespace testbed with physically severed links.

---

## Problem Statement

Conventional secure-gateway architectures suffer from three structural limitations that this
project addresses:

1. **Absence of post-quantum readiness.** Classical key-exchange mechanisms (RSA, ECDH) are
   susceptible to compromise by sufficiently capable quantum computers via Shor's algorithm.
   Traffic recorded today, if encrypted only with classical primitives, remains vulnerable to
   future decryption — a threat model commonly referred to as harvest-now-decrypt-later. This
   is particularly consequential for systems transmitting data with long confidentiality
   lifetimes.

2. **Conflation of security strength with operational context.** A recurring design pattern in
   adaptive-security systems couples cryptographic parameter selection to transient network or
   threat conditions — for example, weakening encryption under battery pressure or strengthening
   it in response to a detected attack. Such coupling introduces a downgrade vulnerability: an
   adversary capable of influencing perceived network or device state can indirectly manipulate
   cryptographic strength. Furthermore, network anomalies and cryptographic strength are governed
   by unrelated threat models — a volumetric attack does not affect the computational hardness of
   a key-exchange problem, and increasing key size does not mitigate a denial-of-service
   condition.

3. **Reactive, rather than proactive, transport resilience.** Standard multihomed transport
   mechanisms detect path failure only after a connection has already been disrupted, resulting
   in avoidable service interruption. There exists an opportunity to apply predictive
   classification of network conditions to anticipate path degradation and initiate failover
   before a hard failure occurs.

This project addresses these limitations by defining two structurally separated control
pathways — one governing cryptographic policy as a function of data sensitivity, and one
governing transport resilience as a function of live network-condition classification and
threat detection — implemented such that neither machine-learning model has any functional
dependency on the cryptographic-parameter-selection logic.

---

## Objectives

1. Design and implement a transparent TCP-to-SCTP gateway that establishes a hybrid
   post-quantum key exchange (X25519 + ML-KEM) with digital-signature-based mutual
   authentication (ML-DSA), without requiring modification of the legacy client.

2. Define and enforce a **Security Policy Engine** in which cryptographic strength is
   determined solely by an explicit data-sensitivity classification (Routine, Sensitive,
   Critical), with ML-KEM-768 as an immutable minimum and ML-KEM-1024 reserved for critical
   classifications, verifiable through automated invariant testing.

3. Design, train, and evaluate a **network-condition classification model** that categorizes
   live transport-path health into five operational states (Stable, Congested, Degraded,
   Unstable, Possible-Path-Failure) using measurable SCTP path metrics, and integrate its output
   into an SCTP transport-policy engine capable of both advisory recommendations and enforced
   proactive failover.

4. Design, train, and evaluate an independent **threat-detection classification model** on a
   public intrusion-detection dataset (CIC-IDS2017) to identify anomalous traffic and drive
   transport-layer mitigation (rate-limiting, alerting), evaluated using a class-stratified split
   and a cross-attack-variant generalization split.

5. Construct a reproducible dual-path network testbed using Linux network namespaces and
   veth interfaces to enable measurement of SCTP failover under conditions of an actually
   severed network link, and quantify failover latency across repeated trials.

6. Provide an observability layer (Streamlit-based dashboard) that visualizes both control
   pathways independently, enabling direct verification that cryptographic parameter selection
   remains unaffected by network-condition and threat-detection outputs.

---

## Methodology

### 4.1 System Architecture

The gateway accepts a plaintext TCP connection from a legacy client and re-originates the
session as an SCTP association secured by a hybrid post-quantum handshake. Two machine-learning
models operate independently downstream of a shared metrics-collection layer: one evaluates
data-plane traffic characteristics for threat indicators, and the other evaluates transport-plane
health metrics for network-condition classification. Their outputs are consumed exclusively by a
Transport Policy Engine. Cryptographic parameter selection is performed by a separate Security
Policy Engine whose sole input is a data-sensitivity classification supplied as a configuration
value, independent of any runtime traffic or network measurement.

### 4.2 Security Policy Engine

The cryptographic strength for a session is computed by a pure function of the form
`select_kem(classification)`, where `classification ∈ {Routine, Sensitive, Critical}`. Routine
and Sensitive classifications resolve to the minimum security floor (hybrid X25519 + ML-KEM-768);
the Critical classification resolves to an elevated parameter set (ML-KEM-1024). The function
signature admits no additional parameters, precluding network metrics, threat-model outputs, or
device-state signals from influencing the result. This property is verified through unit tests
that assert the output is bounded below by the security floor for every possible classification
input, and through code-level enforcement of the function's parameter contract.

### 4.3 Network-Condition Classification and Transport Policy

A RandomForest classifier is trained on five transport-path features — round-trip time, jitter,
packet loss percentage, throughput, and SCTP congestion window — to output one of five ordered
network-condition states. Each state maps deterministically to a transport-policy action:
Stable → normal operation; Congested → congestion response; Degraded → elevated failover
readiness; Unstable → preference for the backup path; Possible-Path-Failure → failover
initiation. A configuration flag (`GW_TRANSPORT_ENFORCE`) governs whether Unstable and
Possible-Path-Failure classifications trigger an advisory log entry or an active path switch,
allowing the system to operate in either a recommendation mode or an enforced proactive-failover
mode depending on the availability of a genuine multi-path transport link.

### 4.4 Threat Detection

A second, independently trained RandomForest classifier evaluates six flow-level statistical
features (mean and standard deviation of inter-arrival time, packet rate, byte rate, mean packet
size, and flow duration) derived from a sliding window of observed traffic, and classifies the
flow into a three-level severity category (Low, Medium, High). The model is trained on the
CIC-IDS2017 intrusion-detection dataset. Its output is consumed exclusively by the Transport
Policy Engine to drive rate-limiting, alerting, and path-selection behavior; it has no pathway
to the Security Policy Engine.

### 4.5 Post-Quantum Secure Channel Establishment

The key-exchange handshake combines a classical X25519 Diffie-Hellman exchange with an ML-KEM
(FIPS 203) key-encapsulation exchange at the parameter level selected by the Security Policy
Engine. Both shared secrets are concatenated and passed through HKDF-SHA-256 to derive a 256-bit
session key, used for AES-256-GCM authenticated encryption of the SCTP payload. Each party holds
a long-term ML-DSA-65 (FIPS 204) signing identity; the handshake transcript is signed by each
side and verified against a pinned public key belonging to the counterparty. A missing or invalid
signature causes the handshake to abort, preventing key substitution by an intermediary.

### 4.6 Experimental Testbed

Two testbed configurations were used for validation:

- **Single-host configuration**, using loopback interfaces, for functional validation of the
  cryptographic handshake, policy-engine invariants, and machine-learning inference pipelines
  without requiring elevated system privileges.
- **Dual-path configuration**, using Linux network namespaces connected by two independent
  virtual Ethernet (veth) links, enabling a network path to be disabled via interface state
  change (`ip link set down`) rather than simulated packet loss. This configuration was used to
  measure SCTP failover behavior under both threat-driven (reactive) and network-condition-driven
  (proactive) triggering conditions across repeated trials, with mean latency and 95% confidence
  interval computed over the trial set.

### 4.7 System Flowchart

```
                              ┌───────────────────────────┐
                              │   Legacy TCP Client        │
                              └─────────────┬─────────────┘
                                            │ plaintext TCP
                                            ▼
                              ┌───────────────────────────┐
                              │   Intelligent Secure Gateway│
                              │   (TCP accept + metrics)   │
                              └──────┬──────────────┬──────┘
                                     │              │
                     data sensitivity│              │traffic & network
                     classification  │              │metrics
                                     ▼              ▼
                  ┌─────────────────────┐   ┌───────────────────────────┐
                  │ Security Policy      │   │ Metrics Distribution      │
                  │ Engine               │   └──────────┬────────┬──────┘
                  │ select_kem(class)    │              │        │
                  └──────────┬──────────┘     flow-stats│        │path-health
                             │                 features │        │features
                  ML-KEM-768 │ (floor)                   ▼        ▼
                  ML-KEM-1024│ (critical only) ┌─────────────┐ ┌──────────────┐
                             │                 │ ML-B: Threat│ │ ML-A: Network │
                             │                 │ Classifier  │ │ Condition     │
                             │                 │ (RandomForest│ │ Classifier    │
                             │                 │  CIC-IDS2017)│ │ (RandomForest)│
                             │                 └──────┬──────┘ └───────┬───────┘
                             │                        │ LOW/MED/HIGH   │STABLE…
                             │                        ▼                │POSSIBLE_
                             │                 ┌────────────────────┐  │PATH_FAILURE
                             │                 │ Transport Policy    │◄─┘
                             │                 │ Engine               │
                             │                 │ (rate-limit / alert /│
                             │                 │  failover readiness /│
                             │                 │  proactive failover) │
                             │                 └──────────┬───────────┘
                             │                            │ transport action
                             ▼                            ▼
                  ┌─────────────────────────────────────────────────┐
                  │  Hybrid Handshake: X25519 + ML-KEM               │
                  │  ML-DSA-65 mutual authentication                 │
                  │  HKDF-SHA-256 session-key derivation             │
                  │  AES-256-GCM authenticated encryption            │
                  └───────────────────────┬───────────────────────┘
                                          │ secured SCTP association
                                          │ (primary + secondary path)
                                          ▼
                              ┌───────────────────────────┐
                              │   SCTP Receiver             │
                              │   (decrypt + verify + relay)│
                              └─────────────┬─────────────┘
                                            ▼
                              ┌───────────────────────────┐
                              │   Destination Endpoint      │
                              └───────────────────────────┘
```

---

## Results

### 5.1 Cryptographic Conformance

Standalone self-tests were executed against the reference Open Quantum Safe (liboqs)
implementation to confirm conformance with standardized parameter sizes:

| Primitive | Parameter | Measured Value | Specification |
|---|---|---|---|
| ML-KEM-768 | Public key | 1184 bytes | FIPS 203 |
| ML-KEM-768 | Secret key | 2400 bytes | FIPS 203 |
| ML-KEM-768 | Ciphertext | 1088 bytes | FIPS 203 |
| ML-KEM-768 | Shared secret | 32 bytes | FIPS 203 |
| ML-DSA-65 | Public key | 1952 bytes | FIPS 204 |
| ML-DSA-65 | Secret key | 4032 bytes | FIPS 204 |
| ML-DSA-65 | Signature (max) | 3309 bytes | FIPS 204 |

Encapsulation/decapsulation agreement, signature verification correctness, and rejection of
tampered ciphertexts, transcripts, and signatures were each confirmed through automated test
execution. Handshake-latency decomposition measurements indicate that ML-KEM computation
constitutes a small fraction (well under 1%) of total handshake duration, with the majority of
elapsed time attributable to network round-trip and session-setup overhead rather than
cryptographic computation.

### 5.2 Security Policy Engine Validation

Automated invariant testing confirmed that the resolved key-encapsulation-mechanism level for
every input classification is bounded at or above the ML-KEM-768 floor, and that the Critical
classification alone resolves to ML-KEM-1024. Live session traces confirmed that resolved
cryptographic strength changes only in response to classification updates and is unaffected by
concurrent variation in network-condition classification or threat-detection output.

### 5.3 Threat Detection Model (ML-B)

| Metric | In-Distribution Split | Cross-Attack-Variant Split |
|---|---|---|
| Accuracy | 0.983 | 0.905 |
| Balanced Accuracy | 0.973 | 0.567 |
| Macro-F1 | 0.874 | 0.575 |
| False-Positive Rate | 0.018 | 0.048 |

The model was compared against a majority-class baseline (macro-F1 0.30) and a logistic-regression
baseline (macro-F1 0.48–0.49), both of which it substantially outperformed. High-severity
(volumetric) attack detection generalized to previously unseen attack variants; medium-severity
detection, corresponding to heterogeneous low-volume reconnaissance activity, exhibited reduced
cross-variant performance, consistent with the absence of a single coherent traffic signature
across that category.

### 5.4 Network-Condition Classification Model (ML-A)

| Metric | RandomForest | Threshold Baseline |
|---|---|---|
| Accuracy | 0.930 | 0.784 |
| Macro-F1 | 0.930 | 0.782 |

Per-class F1 scores ranged from 0.86 (Possible-Path-Failure) to 0.99 (Unstable), with the
principal feature contributions attributed to packet loss (29%), jitter (25%), and round-trip
time (24%).

### 5.5 Failover Behavior

Two independent failover-triggering pathways were implemented and validated over the dual-path
network-namespace testbed: a threat-driven reactive pathway, which initiates failover upon
confirmed primary-path inactivity, and a network-condition-driven proactive pathway, which
initiates failover upon prediction of Unstable or Possible-Path-Failure states in advance of
confirmed path inactivity. Both pathways were confirmed to trigger correctly following a
controlled interface-down event on the primary path, with session continuity maintained via
automatic association migration to the secondary path. Aggregate failover-latency measurement
(mean and 95% confidence interval across repeated trials, disaggregated by triggering pathway) is
obtained via an automated measurement script and is reported per experimental run; representative
single-trial reactive-failover latency was measured at 1715.7 ms, bounded principally by the
transport-layer path-health polling interval.

### 5.6 System Integration

End-to-end functional validation confirmed correct operation of the complete pipeline: legacy
TCP ingress, sliding-window feature extraction, parallel invocation of both classification
models, security-policy resolution, hybrid authenticated key exchange, AES-256-GCM encrypted
relay over a multihomed SCTP association, and metrics persistence to the observability layer.

---

## Conclusion

This project demonstrates that post-quantum cryptographic security, adaptive network resilience,
and machine-learning-based traffic analysis can be integrated within a single transport gateway
while maintaining a strict separation between the mechanisms governing cryptographic strength and
those governing operational response. By constraining cryptographic parameter selection to a
single, explicitly declared input — data sensitivity classification — the system eliminates a
class of downgrade vulnerabilities inherent to designs that couple encryption strength to
transient network or device conditions. The two machine-learning models developed for this
system address distinct, well-defined problems — network-path-health classification and
traffic-based threat detection — each evaluated against measurable baselines rather than assumed
to be effective by construction. The addition of ML-DSA-based transcript authentication closes
an identified gap in the original hybrid key-exchange design, providing resistance to
active adversarial interposition in addition to confidentiality against future cryptanalytic
advances. Validation over a dual-path testbed with physically interrupted network links confirms
that both the reactive and predictive failover mechanisms function as designed under conditions
that approximate real network-path failure.

Future work includes extending validation to a physically distributed two-host testbed to
eliminate shared-kernel and shared-CPU measurement artifacts inherent to the network-namespace
configuration; formal verification of the security-policy floor invariant using a symbolic
protocol-analysis toolchain; and evaluation of the network-condition classification model against
traffic captured from a production or field-representative multi-path network environment.
