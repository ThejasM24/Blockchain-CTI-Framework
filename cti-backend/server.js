const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const axios = require('axios');
const FormData = require('form-data');
const { correlateThreat } = require('./correlation-engine');
const { DatabaseSync } = require('node:sqlite'); // built into Node 22.5+ (no install needed)

const app = express();
app.use(cors({ origin: 'http://localhost:3000' }));
app.use(express.json());

const IPFS_API = 'http://127.0.0.1:5001';
const IPFS_GATEWAY = 'http://127.0.0.1:8080';
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// ---------- Local database (SQLite file: cti-backend/cti.db) ----------
const db = new DatabaseSync(path.join(__dirname, 'cti.db'));
db.exec('PRAGMA journal_mode = WAL;');
db.exec(`
  CREATE TABLE IF NOT EXISTS contributors (
    contributorId       TEXT PRIMARY KEY,
    reputationScore     INTEGER NOT NULL DEFAULT 50,
    totalSubmissions    INTEGER NOT NULL DEFAULT 0,
    validSubmissions    INTEGER NOT NULL DEFAULT 0,
    tamperedSubmissions INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS cti_records (
    indicatorId   TEXT PRIMARY KEY,
    targetIP      TEXT,
    ipfsCID       TEXT NOT NULL,
    cidIsMock     INTEGER NOT NULL DEFAULT 0,
    sha256Hash    TEXT NOT NULL,
    contributorId TEXT NOT NULL,
    category      TEXT,
    status        TEXT NOT NULL DEFAULT 'UNVERIFIED',
    reputationUpdated INTEGER NOT NULL DEFAULT 0,
    timestamp     TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS correlation_results (
    correlationId TEXT PRIMARY KEY,
    indicatorId TEXT NOT NULL,
    category TEXT,
    techniqueId TEXT,
    techniqueName TEXT,
    tactic TEXT,
    tacticalMatchScore INTEGER NOT NULL,
    evidenceCoverage INTEGER NOT NULL,
    evidenceCompleteness INTEGER NOT NULL,
    contributorTrust INTEGER NOT NULL,
    reliabilityIndex INTEGER NOT NULL,
    matchedEvidence TEXT NOT NULL,
    negatedEvidence TEXT NOT NULL,
    explanation TEXT NOT NULL,
    reviewRequired INTEGER NOT NULL,
    createdAt TEXT NOT NULL,
    FOREIGN KEY(indicatorId) REFERENCES cti_records(indicatorId)
  );
  CREATE INDEX IF NOT EXISTS idx_correlation_indicator ON correlation_results(indicatorId, createdAt DESC);
  CREATE TABLE IF NOT EXISTS offchain_store (   -- fallback "IPFS" when the daemon is not running
    cid     TEXT PRIMARY KEY,
    payload TEXT NOT NULL
  );
`);

// Backward-compatible migration for databases created by earlier project versions.
const recordColumns = db.prepare('PRAGMA table_info(cti_records)').all().map(c => c.name);
if (!recordColumns.includes('reputationUpdated')) {
  db.exec('ALTER TABLE cti_records ADD COLUMN reputationUpdated INTEGER NOT NULL DEFAULT 0');
}

// Records that were already verified before this column existed must not earn
// reputation again when they are verified after upgrading.
db.prepare(`
  UPDATE cti_records
  SET reputationUpdated = 1
  WHERE status IN ('VERIFIED', 'TAMPER_DETECTED')
`).run();

const q = {
  insertRecord: db.prepare(`INSERT INTO cti_records
    (indicatorId, targetIP, ipfsCID, cidIsMock, sha256Hash, contributorId, category, status, timestamp)
    VALUES (@indicatorId, @targetIP, @ipfsCID, @cidIsMock, @sha256Hash, @contributorId, @category, @status, @timestamp)`),
  getRecord: db.prepare('SELECT * FROM cti_records WHERE indicatorId = ?'),
  listRecords: db.prepare('SELECT * FROM cti_records ORDER BY timestamp DESC LIMIT 100'),
  setStatus: db.prepare('UPDATE cti_records SET status = ? WHERE indicatorId = ?'),
  markReputationUpdated: db.prepare('UPDATE cti_records SET reputationUpdated = 1 WHERE indicatorId = ? AND reputationUpdated = 0'),
  insertCorrelation: db.prepare(`INSERT INTO correlation_results
    (correlationId, indicatorId, category, techniqueId, techniqueName, tactic, tacticalMatchScore, evidenceCoverage,
     evidenceCompleteness, contributorTrust, reliabilityIndex, matchedEvidence, negatedEvidence, explanation, reviewRequired, createdAt)
    VALUES (@correlationId, @indicatorId, @category, @techniqueId, @techniqueName, @tactic, @tacticalMatchScore, @evidenceCoverage,
     @evidenceCompleteness, @contributorTrust, @reliabilityIndex, @matchedEvidence, @negatedEvidence, @explanation, @reviewRequired, @createdAt)`),
  listCorrelations: db.prepare('SELECT * FROM correlation_results ORDER BY createdAt DESC LIMIT 200'),
  getCorrelationsForIndicator: db.prepare('SELECT * FROM correlation_results WHERE indicatorId = ? ORDER BY createdAt DESC LIMIT 100'),
  getContributor: db.prepare('SELECT * FROM contributors WHERE contributorId = ?'),
  insertContributor: db.prepare('INSERT INTO contributors (contributorId) VALUES (?)'),
  updateContributor: db.prepare(`UPDATE contributors SET reputationScore = @reputationScore,
    totalSubmissions = @totalSubmissions, validSubmissions = @validSubmissions,
    tamperedSubmissions = @tamperedSubmissions WHERE contributorId = @contributorId`),
  listContributors: db.prepare('SELECT * FROM contributors ORDER BY reputationScore DESC'),
  putPayload: db.prepare('INSERT OR REPLACE INTO offchain_store (cid, payload) VALUES (?, ?)'),
  getPayload: db.prepare('SELECT payload FROM offchain_store WHERE cid = ?'),
};

const toRecord = (r) => r && { ...r, cidIsMock: !!r.cidIsMock };

// ---------- STIX-like validation (Validation & Processing layer) ----------
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const CATEGORIES = ['unauthorized-access', 'ddos', 'malware', 'phishing', 'brute-force'];

function validateInput({ targetIP, contributorId, category }) {
  const errors = [];
  if (!IPV4.test(targetIP || '')) errors.push('targetIP must be a valid IPv4 address');
  if (!contributorId || !/^[\w-]{3,40}$/.test(contributorId)) errors.push('contributorId must be 3-40 chars (letters, digits, _ -)');
  if (!CATEGORIES.includes(category)) errors.push(`category must be one of: ${CATEGORIES.join(', ')}`);
  return errors;
}

// ---------- IPFS (Off-chain storage) ----------
async function uploadToIPFS(payloadString) {
  try {
    const form = new FormData();
    form.append('file', Buffer.from(payloadString), { filename: 'cti_payload.json' });
    const r = await axios.post(`${IPFS_API}/api/v0/add`, form, { headers: form.getHeaders(), timeout: 3000 });
    return { cid: r.data.Hash, mock: false };
  } catch {
    const cid = `MOCK-Qm${sha256(payloadString).slice(0, 44)}`;
    q.putPayload.run(cid, payloadString);
    return { cid, mock: true };
  }
}

async function fetchFromIPFS(cid) {
  if (cid.startsWith('MOCK-')) {
    const row = q.getPayload.get(cid);
    if (!row) throw new Error('Off-chain payload not found');
    return row.payload;
  }
  const r = await axios.get(`${IPFS_GATEWAY}/ipfs/${cid}`, { timeout: 5000, responseType: 'text', transformResponse: (d) => d });
  return r.data; // raw string, exactly as stored
}

// ---------- Reputation (behaviour-driven) ----------
function updateReputation(contributorId, ok) {
  if (!q.getContributor.get(contributorId)) q.insertContributor.run(contributorId);
  const c = q.getContributor.get(contributorId);
  c.totalSubmissions += 1;
  if (ok) { c.validSubmissions += 1; c.reputationScore = Math.min(100, c.reputationScore + 2); }
  else { c.tamperedSubmissions += 1; c.reputationScore = Math.max(0, c.reputationScore - 15); }
  q.updateContributor.run(c);
}

// ---------- Core logic ----------
async function ingest({ targetIP, contributorId, category }) {
  const id = `indicator--${crypto.randomUUID()}`;
  const stix = {
    type: 'indicator', spec_version: '2.1', id,
    created: new Date().toISOString(),
    contributor_id: contributorId,
    labels: [category],
    pattern: `[ipv4-addr:value = '${targetIP}']`,
  };
  const payloadString = JSON.stringify(stix);
  const hash = sha256(payloadString);           // hash taken BEFORE it leaves our control
  const { cid, mock } = await uploadToIPFS(payloadString);
  const record = {
    indicatorId: id, targetIP, ipfsCID: cid, cidIsMock: mock ? 1 : 0, sha256Hash: hash,
    contributorId, category, status: 'UNVERIFIED', timestamp: new Date().toISOString(),
  };
  q.insertRecord.run(record);
  if (!q.getContributor.get(contributorId)) q.insertContributor.run(contributorId);
  return toRecord(record);
}

async function verify(record, simulateTamper) {
  // Real check: re-fetch from off-chain storage, recompute hash, compare with the anchored one
  let fetched = await fetchFromIPFS(record.ipfsCID);
  if (simulateTamper) {
    // Adversary modifies the off-chain copy
    const obj = JSON.parse(fetched);
    obj.pattern = `[ipv4-addr:value = '6.6.6.6']`;
    fetched = JSON.stringify(obj);
  }
  const computed = sha256(fetched);
  const intact = computed === record.sha256Hash;
  q.setStatus.run(intact ? 'VERIFIED' : 'TAMPER_DETECTED', record.indicatorId);
  // Claim the one-time reputation update and update the contributor in one
  // SQLite transaction so concurrent/repeated requests cannot award twice.
  let firstVerification = false;
  db.exec('BEGIN IMMEDIATE');
  try {
    firstVerification = q.markReputationUpdated.run(record.indicatorId).changes === 1;
    if (firstVerification) updateReputation(record.contributorId, intact);
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }

  return {
    intact,
    expectedHash: record.sha256Hash,
    computedHash: computed,
    reputationUpdated: firstVerification
  };
}

// ---------- Routes ----------
app.post('/api/cti/submit', async (req, res) => {
  const errors = validateInput(req.body);
  if (errors.length) return res.status(400).json({ success: false, errors });
  try { res.json({ success: true, record: await ingest(req.body) }); }
  catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/cti/verify/:id', async (req, res) => {
  try {
    const record = q.getRecord.get(req.params.id);
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });
    const result = await verify(record, !!req.body.simulateTamper);
    res.json({
      success: true,
      status: result.intact ? 'VERIFIED' : 'TAMPER_DETECTED',
      ...result,
      message: result.intact
        ? '[VERIFICATION PASSED] Off-chain payload matches the anchored SHA-256 hash.'
        : '[RED ALERT] TAMPER DETECTED - off-chain payload hash does not match the anchored hash.',
    });
  } catch (e) { res.status(500).json({ success: false, error: `Verification failed: ${e.message}` }); }
});

// Tactical-to-technical correlation extension. This is a transparent
// rule-based research prototype; it does not perform validated attribution.
app.post('/api/cti/correlate/:id', (req, res) => {
  try {
    const record = q.getRecord.get(req.params.id);
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });
    const contributor = q.getContributor.get(record.contributorId);
    const result = correlateThreat({
      category: record.category,
      observedBehavior: req.body.observedBehavior || '',
      evidenceText: req.body.evidenceText || '',
      contributorScore: contributor ? contributor.reputationScore : 50,
    });
    const saved = {
      correlationId: `correlation--${crypto.randomUUID()}`,
      indicatorId: record.indicatorId,
      category: record.category,
      techniqueId: result.techniqueId,
      techniqueName: result.techniqueName,
      tactic: result.tactic,
      tacticalMatchScore: result.tacticalMatchScore,
      evidenceCoverage: result.evidenceCoverage,
      evidenceCompleteness: result.evidenceCompleteness,
      contributorTrust: result.contributorTrust,
      reliabilityIndex: result.reliabilityIndex,
      matchedEvidence: JSON.stringify(result.matchedEvidence || []),
      negatedEvidence: JSON.stringify(result.negatedEvidence || []),
      explanation: result.explanation,
      reviewRequired: result.reviewRequired ? 1 : 0,
      createdAt: new Date().toISOString(),
    };
    q.insertCorrelation.run(saved);
    res.json({ success: true, indicatorId: record.indicatorId, targetIP: record.targetIP, category: record.category,
      correlationId: saved.correlationId, ...result });
  } catch (e) {
    res.status(500).json({ success: false, error: `Correlation failed: ${e.message}` });
  }
});

app.get('/api/cti/records', (_req, res) => {
  try {
    res.json({ success: true, data: q.listRecords.all().map(toRecord), contributors: q.listContributors.all() });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// Auditable history of previously generated tactical-to-technical correlations.
app.get('/api/cti/correlations', (_req, res) => {
  try {
    const rows = q.listCorrelations.all().map(r => ({
      ...r,
      matchedEvidence: JSON.parse(r.matchedEvidence),
      negatedEvidence: JSON.parse(r.negatedEvidence),
      reviewRequired: !!r.reviewRequired,
    }));
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/api/cti/correlations/:id', (req, res) => {
  try {
    const rows = q.getCorrelationsForIndicator.all(req.params.id).map(r => ({
      ...r,
      matchedEvidence: JSON.parse(r.matchedEvidence),
      negatedEvidence: JSON.parse(r.negatedEvidence),
      reviewRequired: !!r.reviewRequired,
    }));
    res.json({ success: true, indicatorId: req.params.id, data: rows });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// Real benchmark: N ingest+verify cycles, measured (not hard-coded)
app.post('/api/cti/benchmark', async (req, res) => {
  const n = Math.min(Math.max(parseInt(req.body.count, 10) || 20, 1), 200);
  const lat = [];
  const start = process.hrtime.bigint();
  try {
    for (let i = 0; i < n; i++) {
      const t0 = process.hrtime.bigint();
      const rec = await ingest({ targetIP: `10.0.${i % 256}.${(i * 7) % 256}`, contributorId: 'Benchmark-Org', category: 'ddos' });
      await verify(q.getRecord.get(rec.indicatorId), false);
      lat.push(Number(process.hrtime.bigint() - t0) / 1e6);
    }
    const totalSec = Number(process.hrtime.bigint() - start) / 1e9;
    lat.sort((a, b) => a - b);
    res.json({
      success: true,
      benchmark: {
        transactions: n,
        throughputTPS: +(n / totalSec).toFixed(2),
        avgLatencyMs: +(lat.reduce((a, b) => a + b, 0) / n).toFixed(2),
        p95LatencyMs: +lat[Math.max(Math.floor(n * 0.95) - 1, 0)].toFixed(2),
        note: 'Measured on this Node.js + SQLite prototype (not Hyperledger Caliper).',
      },
    });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.listen(5000, () => console.log('CTI API on http://localhost:5000 (SQLite DB: cti-backend/cti.db)'));
