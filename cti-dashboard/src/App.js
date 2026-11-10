import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import './App.css';

const API = 'http://localhost:5000/api/cti';
const CATEGORIES = ['unauthorized-access', 'ddos', 'malware', 'phishing', 'brute-force'];

const box = { background: '#f4f4f4', padding: 15, borderRadius: 6, marginTop: 15 };
const btn = (bg) => ({ padding: '8px 16px', background: bg, color: 'white', border: 'none', borderRadius: 4, cursor: 'pointer', marginRight: 8 });

export default function App() {
  const [form, setForm] = useState({ targetIP: '192.168.1.105', contributorId: 'SOC-Org-Alpha', category: 'unauthorized-access' });
  const [record, setRecord] = useState(null);
  const [simulateTamper, setSimulateTamper] = useState(false);
  const [result, setResult] = useState(null);
  const [correlation, setCorrelation] = useState(null);
  const [observedBehavior, setObservedBehavior] = useState('Repeated login attempts were observed from the source IP.');
  const [evidenceText, setEvidenceText] = useState('Logs show failed login, password guessing, and repeated login attempts.');
  const [error, setError] = useState('');
  const [records, setRecords] = useState([]);
  const [contributors, setContributors] = useState([]);
  const [bench, setBench] = useState(null);
  const [busy, setBusy] = useState(false);
  const [theme, setTheme] = useState('dark');

  const refresh = useCallback(async () => {
    try {
      const { data } = await axios.get(`${API}/records`);
      setRecords(data.data);
      setContributors(data.contributors);
    } catch { setError('Cannot reach backend on port 5000. Is it running?'); }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const call = async (fn) => {
    setBusy(true); setError('');
    try { await fn(); await refresh(); }
    catch (e) { setError(e.response?.data?.errors?.join(', ') || e.response?.data?.error || e.message); }
    finally { setBusy(false); }
  };

  const submit = () => call(async () => {
    const { data } = await axios.post(`${API}/submit`, form);
    setRecord(data.record); setResult(null); setCorrelation(null);
  });

  const verify = () => call(async () => {
    const { data } = await axios.post(`${API}/verify/${record.indicatorId}`, { simulateTamper });
    setResult(data);
  });

  const runCorrelation = () => call(async () => {
    const { data } = await axios.post(`${API}/correlate/${record.indicatorId}`, { observedBehavior, evidenceText });
    setCorrelation(data);
  });

  const runBenchmark = () => call(async () => {
    const { data } = await axios.post(`${API}/benchmark`, { count: 20 });
    setBench(data.benchmark);
  });

  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  return (
    <div className={`dashboard ${theme}`}>
      <header className="dashboard-header">
        <div>
          <div className="eyebrow">CYBER THREAT INTELLIGENCE PLATFORM</div>
          <h1>Blockchain-Based CTI Dashboard</h1>
          <p>Ingestion, integrity verification and tactical–technical correlation</p>
        </div>
        <button className="theme-toggle" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} aria-label="Toggle colour theme">
          {theme === 'dark' ? '☀ Light mode' : '☾ Dark mode'}
        </button>
      </header>
      <div className="dashboard-content">
      <p className="intro">Prototype extension: correlate technical indicators with reported attack behaviour and supporting evidence.</p>

      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <input value={form.targetIP} onChange={set('targetIP')} placeholder="Target IPv4" />
        <input value={form.contributorId} onChange={set('contributorId')} placeholder="Contributor ID" />
        <select value={form.category} onChange={set('category')}>
          {CATEGORIES.map((c) => <option key={c}>{c}</option>)}
        </select>
        <button disabled={busy} onClick={submit} style={btn('#28a745')}>Submit CTI</button>
      </div>

      {error && <div style={{ ...box, background: '#fdecea', color: '#b71c1c' }}>{error}</div>}

      {record && (
        <div style={box}>
          <h3>Ledger Entry Created</h3>
          <p><b>ID:</b> {record.indicatorId}</p>
          <p><b>IPFS CID:</b> {record.ipfsCID} {record.cidIsMock && <em>(mock - IPFS daemon not running)</em>}</p>
          <p style={{ wordBreak: 'break-all' }}><b>SHA-256:</b> {record.sha256Hash}</p>
          <label>
            <input type="checkbox" checked={simulateTamper} onChange={(e) => setSimulateTamper(e.target.checked)} />
            {' '}Simulate off-chain payload modification
          </label>
          <br /><br />
          <button disabled={busy} onClick={verify} style={btn('#007bff')}>Run Tamper Verification</button>
          <div style={{ marginTop: 20, borderTop: '1px solid #ddd', paddingTop: 12 }}>
            <h3>Context-Aware Tactical–Technical Correlation</h3>
            <p style={{ marginBottom: 6 }}>Observed attack behaviour</p>
            <textarea rows="3" value={observedBehavior} onChange={(e) => setObservedBehavior(e.target.value)} style={{ width: '100%', boxSizing: 'border-box', padding: 8 }} placeholder="Describe what the security team observed" />
            <p style={{ marginBottom: 6 }}>Supporting evidence / log summary</p>
            <textarea rows="3" value={evidenceText} onChange={(e) => setEvidenceText(e.target.value)} style={{ width: '100%', boxSizing: 'border-box', padding: 8 }} placeholder="Paste a short, sanitized log summary or evidence description" />
            <button disabled={busy} onClick={runCorrelation} style={{ ...btn('#6f42c1'), marginTop: 10 }}>Run Tactical–Technical Correlation</button>
          </div>
        </div>
      )}

      {correlation && (
        <div style={{ ...box, background: '#eef2ff' }}>
          <h3>Correlation Result (Prototype)</h3>
          <p><b>MITRE ATT&amp;CK candidate:</b> {correlation.techniqueId ? `${correlation.techniqueId} — ${correlation.techniqueName}` : 'Not configured'}</p>
          <p><b>Tactic:</b> {correlation.tactic || 'N/A'}</p>
          <p><b>Tactical match score:</b> {correlation.tacticalMatchScore}/100</p>
          <p><b>Evidence coverage:</b> {correlation.evidenceCoverage}%</p>
          <p><b>Evidence completeness:</b> {correlation.evidenceCompleteness}%</p>
          <p><b>Contributor trust:</b> {correlation.contributorTrust}/100</p>
          <p><b>Overall reliability index:</b> {correlation.reliabilityIndex}/100</p>
          <p><b>Matched evidence:</b> {correlation.matchedEvidence.length ? correlation.matchedEvidence.join(', ') : 'No positive evidence matched'}</p>
          {correlation.negatedEvidence.length > 0 && <p><b>Negated evidence excluded:</b> {correlation.negatedEvidence.join(', ')}</p>}
          <p>{correlation.explanation}</p>
          <small>These are transparent rule-based heuristic indicators, not probabilities or validated threat attribution. ATT&amp;CK candidates and evidence require human review. {correlation.reviewRequired ? 'Manual review is recommended.' : 'Review the mapping before operational use.'}</small>
        </div>
      )}

      {result && (
        <div style={{ ...box, background: result.intact ? '#e8f5e9' : '#fdecea', color: result.intact ? '#1b5e20' : '#b71c1c', wordBreak: 'break-all' }}>
          <b>{result.message}</b>
          <p>Expected: {result.expectedHash}</p>
          <p>Computed: {result.computedHash}</p>
        </div>
      )}

      <h3 style={{ marginTop: 30 }}>Contributor Reputation</h3>
      <table border="1" cellPadding="6" style={{ borderCollapse: 'collapse', width: '100%' }}>
        <thead><tr><th>Contributor</th><th>Score</th><th>Total</th><th>Valid</th><th>Tampered</th></tr></thead>
        <tbody>
          {contributors.map((c) => (
            <tr key={c.contributorId}>
              <td>{c.contributorId}</td><td>{c.reputationScore}</td>
              <td>{c.totalSubmissions}</td><td>{c.validSubmissions}</td><td>{c.tamperedSubmissions}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3 style={{ marginTop: 30 }}>CTI Records</h3>
      <table border="1" cellPadding="6" style={{ borderCollapse: 'collapse', width: '100%', fontSize: 13 }}>
        <thead><tr><th>IP</th><th>Category</th><th>Contributor</th><th>Status</th><th>Time</th></tr></thead>
        <tbody>
          {records.map((r) => (
            <tr key={r.indicatorId}>
              <td>{r.targetIP}</td><td>{r.category}</td><td>{r.contributorId}</td>
              <td style={{ color: r.status === 'TAMPER_DETECTED' ? 'red' : r.status === 'VERIFIED' ? 'green' : '#666' }}>{r.status}</td>
              <td>{new Date(r.timestamp).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3 style={{ marginTop: 30 }}>Performance Benchmark</h3>
      <button disabled={busy} onClick={runBenchmark} style={btn('#6f42c1')}>Run Benchmark (20 tx)</button>
      {bench && (
        <div style={box}>
          <p><b>Transactions:</b> {bench.transactions}</p>
          <p><b>Throughput:</b> {bench.throughputTPS} TPS</p>
          <p><b>Avg latency:</b> {bench.avgLatencyMs} ms &nbsp; <b>P95:</b> {bench.p95LatencyMs} ms</p>
          <small>{bench.note}</small>
        </div>
      )}
      </div>
    </div>
  );
}
