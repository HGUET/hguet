# Blind review of the 30 critical cases

Critical = the additional-true-positive scenarios and the false-accusation traps: the cases where a wrong
label would most distort the benchmark.

## For the reviewer

1. Work **only** from the case file (`CV-###.json` in this folder). Do not open `../../truth/`, the generator
   (`../../tools/`), reports, scenario titles or `../QUALITY.md`.
2. Each file lists the transaction's instructions, the subjects to assess, the reference time, the network, and
   **all** independent evidence about those subjects (including retractions and evidence for other networks).
3. Decide **BAD** (the transaction is harmful and the evidence supports saying so), **GOOD** (the evidence
   supports it being legitimate), or **UNKNOWN** (the evidence does not decide). Apply only what the evidence
   fields say: network, validity window, retraction, tier, confidence, polarity.
4. Copy the file to `../responses/<your-id>/CV-###.json`, fill `questions.verdict`, `confidence_0_to_1`,
   `decisive_evidence_ids` and `reasoning`. Do not discuss answers with other reviewers before submitting.

## For the benchmark owner

`python testing/cloud-value/labeling/score_review.py` compares responses with the hidden truth and writes
`../review_results.json`. Labels count as independently reviewed only with **two or more** reviewers who
answered all 30 cases. Disagreements are resolved in writing by a human; the script never edits `truth/`.

Status today: **no reviewer has responded.** The synthetic evidence describes documented attack *classes*; it is
not a claim that any real incident occurred.
