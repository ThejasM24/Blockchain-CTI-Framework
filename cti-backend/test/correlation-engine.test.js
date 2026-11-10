const test = require('node:test');
const assert = require('node:assert/strict');
const { correlateThreat } = require('../correlation-engine');

test('positive brute-force evidence produces a candidate mapping', () => {
  const result = correlateThreat({
    category: 'brute-force',
    observedBehavior: 'Repeated login attempts were observed from one host.',
    evidenceText: 'Logs show failed login and password guessing.',
    contributorScore: 52,
  });
  assert.equal(result.matched, true);
  assert.equal(result.techniqueId, 'T1110');
  assert.ok(result.evidenceCoverage > 0);
});

test('negated brute-force evidence is not counted as positive', () => {
  const result = correlateThreat({
    category: 'brute-force',
    observedBehavior: 'No repeated login attempts were observed.',
    evidenceText: 'No failed login was detected and there was no password guessing.',
    contributorScore: 52,
  });
  assert.equal(result.matched, false);
  assert.equal(result.evidenceCoverage, 0);
  assert.ok(result.negatedEvidence.length > 0);
  assert.equal(result.reviewRequired, true);
});

test('unknown category safely requests manual review', () => {
  const result = correlateThreat({ category: 'unknown-category' });
  assert.equal(result.techniqueId, null);
  assert.equal(result.reviewRequired, true);
});


test('mixed evidence keeps positive matches and separately records negated phrases', () => {
  const result = correlateThreat({
    category: 'brute-force',
    observedBehavior: 'Repeated login attempts were observed from one host.',
    evidenceText: 'Logs show failed login. Password guessing was not detected.',
    contributorScore: 52,
  });
  assert.equal(result.matched, true);
  assert.ok(result.matchedEvidence.includes('repeated login'));
  assert.ok(result.negatedEvidence.includes('password guessing'));
  assert.equal(result.matchedEvidence.includes('password guessing'), false);
});
