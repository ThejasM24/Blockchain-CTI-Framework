const mappings = require('./data/attack-mappings.json');

// Transparent, keyword-based prototype. Scores are heuristic indicators,
// not probabilities and not validated threat attribution.
const NEGATION_TERMS = [
  'no', 'not', 'never', 'without', 'neither', 'absence of', 'lack of',
  'failed to detect', 'not detected', 'was not observed', 'were not observed'
];

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\\]\\]/g, '\\$&');
}

function isNegated(text, start, end) {
  const before = text.slice(Math.max(0, start - 70), start);
  const after = text.slice(end, Math.min(text.length, end + 45));
  // Limit the scope to nearby words so a negation elsewhere in a long report
  // does not automatically cancel an unrelated positive observation.
  const beforeWindow = before.split(/[.!?;\n]/).pop() || before;
  const afterWindow = after.split(/[.!?;\n]/)[0] || after;
  const beforeWords = beforeWindow.trim().split(/\s+/).slice(-6).join(' ');
  const afterWords = afterWindow.trim().split(/\s+/).slice(0, 4).join(' ');
  return NEGATION_TERMS.some(term =>
    new RegExp(`(?:^|\\b)${escapeRegex(term)}(?:\\b|$)`, 'i').test(beforeWords) ||
    new RegExp(`(?:^|\\b)${escapeRegex(term)}(?:\\b|$)`, 'i').test(afterWords)
  );
}

function findMatches(text, keywords) {
  const positive = [];
  const negated = [];
  for (const keyword of keywords || []) {
    const escaped = escapeRegex(keyword);
    const regex = new RegExp(`\\b${escaped}\\b`, 'gi');
    let match;
    let positiveFound = false;
    let negativeFound = false;
    while ((match = regex.exec(text)) !== null) {
      if (isNegated(text, match.index, match.index + match[0].length)) negativeFound = true;
      else positiveFound = true;
      if (match[0].length === 0) regex.lastIndex++;
    }
    if (positiveFound) positive.push(keyword);
    else if (negativeFound) negated.push(keyword);
  }
  return { positive, negated };
}

function correlateThreat({ category, observedBehavior = '', evidenceText = '', contributorScore = 50 }) {
  const mapping = mappings[category];
  const trust = Math.max(0, Math.min(100, Number(contributorScore) || 0));
  if (!mapping) {
    return {
      matched: false, techniqueId: null, techniqueName: null, tactic: null,
      tacticalMatchScore: 0, evidenceCoverage: 0, evidenceCompleteness: 0,
      contributorTrust: trust, reliabilityIndex: 0, scoreType: 'heuristic',
      explanation: 'No ATT&CK candidate is configured for this category.',
      matchedEvidence: [], negatedEvidence: [], reviewRequired: true
    };
  }

  const behavior = String(observedBehavior).toLowerCase();
  const evidence = String(evidenceText).toLowerCase();
  const behaviorMatches = findMatches(behavior, mapping.keywords);
  const evidenceMatches = findMatches(evidence, mapping.keywords);
  const matchedEvidence = [...new Set([...behaviorMatches.positive, ...evidenceMatches.positive])];
  const negatedEvidence = [...new Set([...behaviorMatches.negated, ...evidenceMatches.negated])]
    .filter(k => !matchedEvidence.includes(k));
  const keywordCount = (mapping.keywords || []).length;
  const evidenceCoverage = keywordCount ? Math.round(matchedEvidence.length / keywordCount * 100) : 0;
  const hasBehavior = behavior.trim().length >= 10;
  const hasEvidence = evidence.trim().length >= 10;
  const evidenceCompleteness = (hasBehavior ? 50 : 0) + (hasEvidence ? 50 : 0);
  const tacticalMatchScore = Math.round(evidenceCoverage * 0.8 + (hasBehavior && matchedEvidence.length ? 20 : 0));
  const reliabilityIndex = Math.round(trust * 0.5 + evidenceCoverage * 0.3 + evidenceCompleteness * 0.2);
  const matched = matchedEvidence.length > 0;
  let explanation;
  if (matched) {
    explanation = `${matchedEvidence.length} of ${keywordCount} configured evidence phrases matched positively.`;
    if (negatedEvidence.length) explanation += ` ${negatedEvidence.length} phrase(s) were excluded because they appeared in a nearby negated context.`;
    explanation += ' Reliability combines contributor reputation (50%), evidence coverage (30%), and evidence completeness (20%).';
  } else if (negatedEvidence.length) {
    explanation = 'No positive evidence matched. Configured phrases appeared only in a nearby negated context. Manual review is recommended.';
  } else {
    explanation = 'No configured evidence phrase matched. Treat this candidate mapping as weak and review it manually.';
  }

  return {
    matched, techniqueId: mapping.techniqueId, techniqueName: mapping.techniqueName,
    tactic: mapping.tactic, tacticalMatchScore, evidenceCoverage,
    evidenceCompleteness, contributorTrust: trust, reliabilityIndex,
    scoreType: 'heuristic', explanation, matchedEvidence, negatedEvidence,
    reviewRequired: !matched || reliabilityIndex < 60
  };
}

module.exports = { correlateThreat };
