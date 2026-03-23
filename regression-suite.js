const fs = require('fs');
const path = require('path');

function safeReadJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function normalizeRisk(value) {
  return String(value || '').trim();
}

function resolveTitle(testCase, index) {
  return (
    testCase.id ||
    testCase.name ||
    `${testCase.category || 'unknown'}_${testCase.difficulty || 'unknown'}_${index + 1}`
  );
}

async function runRegressionSuite(options = {}) {
  const {
    analyze,
    casesPath = path.join(__dirname, 'test-cases.json')
  } = options;

  if (typeof analyze !== 'function') {
    throw new Error('runRegressionSuite requires an analyze(text, testCase) function.');
  }

  const cases = safeReadJson(casesPath);

  if (!Array.isArray(cases)) {
    throw new Error('test-cases.json must contain an array of test cases.');
  }

  const results = [];
  let passCount = 0;

  for (let index = 0; index < cases.length; index += 1) {
    const testCase = cases[index];
    const text = String(testCase?.text || '');
    const expectedRisk = normalizeRisk(testCase?.expected?.risk);
    const id = resolveTitle(testCase, index);

    let analysis;
    let pass = false;
    let error = null;

    try {
      analysis = await analyze(text, testCase);

      const actualRisk = normalizeRisk(analysis?.risk);
      pass = actualRisk === expectedRisk;

      if (pass) {
        passCount += 1;
      }
    } catch (err) {
      error = err?.message || String(err);
      analysis = null;
      pass = false;
    }

    results.push({
      id,
      category: testCase?.category || 'n/a',
      difficulty: testCase?.difficulty || 'n/a',
      expectedRisk,
      actualRisk: normalizeRisk(analysis?.risk),
      score: Number.isFinite(analysis?.riskScore) ? analysis.riskScore : null,
      scamType: analysis?.scamType || '',
      pass,
      error
    });
  }

  return {
    summary: {
      total: results.length,
      passed: passCount,
      failed: results.length - passCount,
      passRate: results.length ? Number(((passCount / results.length) * 100).toFixed(1)) : 0
    },
    results
  };
}

module.exports = {
  runRegressionSuite
};