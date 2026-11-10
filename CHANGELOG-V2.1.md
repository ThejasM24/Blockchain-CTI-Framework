# Extended V2.1 changes

## Fixed
- Contributor reputation is now updated only on the first verification of each CTI record. Repeated verification requests no longer repeatedly increase or decrease the contributor score.
- Existing SQLite databases are migrated automatically by adding `cti_records.reputationUpdated` when absent.

## Added
- SQLite `correlation_results` audit table with a unique correlation ID, indicator ID, candidate ATT&CK mapping, heuristic scores, matched/negated evidence, explanation, review flag, and timestamp.
- `GET /api/cti/correlations` returns the latest 200 saved correlation results.
- `GET /api/cti/correlations/:id` returns the latest 100 saved results for an indicator.
- Each successful `POST /api/cti/correlate/:id` call is persisted and returns its `correlationId`.
- Mixed-evidence unit test.

## Verification performed for this package
- Four correlation-engine unit tests passed.
- Backend JavaScript syntax checks passed.
- Isolated SQLite checks passed for the one-time reputation guard and correlation-history insert/read.
- Full Express API and React dashboard runtime/build were not run in this environment because dependencies are not installed here. Install dependencies and run the Windows steps in README.md to complete local integration testing.
