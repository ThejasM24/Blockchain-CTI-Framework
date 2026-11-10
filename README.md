# Blockchain-Based Tamper-Resistant CTI Framework — Extended Prototype

This project combines the original CTI ingestion and integrity-verification prototype with an added **context-aware tactical-to-technical correlation module**.

## What is included

### Original project features retained
- IPv4 CTI submission with contributor identifier and threat category validation.
- STIX 2.1-style indicator payload creation.
- Off-chain payload storage: uses a local IPFS daemon when available and a clearly labelled SQLite mock fallback when it is not.
- SHA-256 payload integrity checking and a tampering simulation.
- Contributor reputation counters and score updates (now applied only once per CTI record, preventing repeated-click score inflation).
- React dashboard and measured local ingest/verify benchmark.

### Added research-prototype extension
- Maps supported CTI categories to candidate MITRE ATT&CK technique/tactic entries.
- Accepts an observed-behaviour description and supporting evidence/log summary.
- Calculates keyword evidence coverage, evidence completeness, contributor trust, and a combined reliability index.
- Detects nearby negation terms (for example, “no failed login”) and excludes those keyword occurrences from positive evidence matches.
- Displays matched and negated evidence and flags weak results for manual review.
- Persists each correlation result in SQLite with a timestamp and unique correlation ID; exposes endpoints to retrieve audit history.

**Important scope note:** The supplied backend stores its ledger records in SQLite. The included IPFS fallback is a mock local payload store when IPFS is unavailable. This code does not deploy a blockchain network or smart contract. The included benchmark is a Node.js/SQLite prototype benchmark, not Hyperledger Caliper. The correlation engine is rule-based and heuristic; its scores are not probabilities, validated attribution, or proof of an attack. MITRE ATT&CK mappings and evidence must be reviewed by a human. Do not use this prototype as an automated production blocking/response system.

## Project structure

```text
BlockchainCTIFramework-main/
├── cti-backend/
│   ├── data/attack-mappings.json
│   ├── test/correlation-engine.test.js
│   ├── correlation-engine.js
│   ├── server.js
│   └── package.json
└── cti-dashboard/
    └── src/App.js
```

## Requirements
- Node.js 22.5 or later (the backend uses the built-in `node:sqlite` module).
- npm.
- IPFS Desktop/daemon is optional; without it, the application uses its mock fallback.

## Run on Windows (VS Code)

Open the project folder in VS Code. Start two terminals.

**Terminal 1 — backend**

```powershell
cd cti-backend
npm install
npm test
npm start
```

Backend API: `http://localhost:5000`

**Terminal 2 — React dashboard**

```powershell
cd cti-dashboard
npm install
npm start
```

Dashboard: `http://localhost:3000`

If the React app uses a different port, update the CORS origin in `cti-backend/server.js`.

## Demonstration workflow

1. Submit an IPv4 address, contributor ID, and category.
2. Run tamper verification with the simulation checkbox off; the payload should verify if the stored copy is unchanged.
3. For a separate demo record, turn the tamper simulation on and run verification; the computed hash should differ and the record should be marked tampered. Reputation is adjusted only on the first verification for each record, so repeated clicks cannot inflate or repeatedly reduce the score.
4. In the selected record panel, enter observed behaviour and supporting evidence, then run tactical–technical correlation.
5. Try both positive and negative evidence. For example:
   - Positive: `Repeated login attempts were observed.` / `Logs show failed login and password guessing.`
   - Negative: `No repeated login attempts were observed.` / `No failed login was detected.`
6. Review the candidate technique, matched/negated phrases, heuristic scores, and manual-review warning.
7. Run the local benchmark and report the actual values displayed by your machine; do not copy sample numbers as results.

## API added

`POST /api/cti/correlate/:id`

Example JSON body:

```json
{
  "observedBehavior": "Repeated login attempts were observed from one host.",
  "evidenceText": "Logs show failed login and password guessing."
}
```

The endpoint uses the selected CTI record's category and the contributor's current reputation score. It returns the candidate ATT&CK mapping, heuristic scores, matched evidence, negated evidence, and whether manual review is recommended. Every call is saved to the SQLite `correlation_results` table.

Additional history endpoints:
- `GET /api/cti/correlations` — latest 200 correlation records.
- `GET /api/cti/correlations/:id` — latest 100 correlation records for one indicator ID.

The `cti_records.reputationUpdated` field is added automatically when an older SQLite database is opened, so existing local databases are migrated without deleting records.

## Tests

From `cti-backend` run:

```powershell
npm test
```

The tests cover positive matching, fully negated evidence, mixed positive/negated evidence, and unknown categories. The verification reputation guard and correlation-history persistence are implemented in the API/database layer; run the application locally to exercise those routes. They do not validate the scientific accuracy of ATT&CK attribution or replace broader integration/security testing.

## Research contribution to discuss with the project guide

The proposed extension is **context-aware tactical-to-technical CTI correlation with negation-aware evidence validation and contributor-trust-informed reliability scoring**. It extends the existing integrity and reputation workflow by examining whether the submitted technical category is supported by the reported behaviour and evidence. Treat this as a proposed contribution until you complete a literature review and obtain guide approval.


## Dashboard theme (V2.3)
The dashboard now opens in dark mode and includes a Light mode / Dark mode toggle in the header. The theme change is frontend-only and does not alter backend APIs or stored CTI data.
