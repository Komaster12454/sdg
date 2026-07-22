# Security and Responsible Disclosure

SDG is a defensive intelligence monitor. Zero-day output is a candidate signal, not proof that a vulnerability is exploitable.

When SDG surfaces a potential previously unreported vulnerability:

1. Verify that testing is explicitly authorized.
2. Reproduce in a controlled environment using the least intrusive method available.
3. Do not collect unrelated data or access other users' information.
4. Preserve a concise timeline, affected versions, impact, and non-destructive reproduction notes.
5. Contact the vendor's PSIRT or CNA. CERT/CC can assist when no appropriate vendor channel exists.
6. Coordinate publication and CVE assignment with the vendor/CNA.
7. Keep exploit payloads, credentials, and sensitive evidence out of public Discord channels and this repository.

False positives can be suppressed with `SUPPRESS_IDENTIFIERS`; candidate sensitivity can be tuned with `MIN_ZERO_DAY_SCORE` and `MIN_ZERO_DAY_CONFIDENCE`.
