const { runRegressionSuite } = require('./regression-suite');
const { buildAnalysis, normalizeText } = require('./server');

async function run() {
  const report = await runRegressionSuite({
    analyze: async (text) =>
      buildAnalysis({
        text: normalizeText(text),
        sourceType: 'text'
      })
  });

  for (const result of report.results) {
    console.log(`
=== ${result.id} ===`);
    console.log(`Category: ${result.category}`);
    console.log(`Difficulty: ${result.difficulty}`);
    console.log(`Expected: ${result.expectedRisk}`);
    console.log(`Actual:   ${result.actualRisk || 'ERROR'}`);
    console.log(`Score:    ${result.score ?? 'n/a'}`);
    console.log(`Type:     ${result.scamType || 'n/a'}`);
    console.log(`Result:   ${result.pass ? 'PASS' : 'FAIL ❌'}`);

    if (result.error) {
      console.log(`Error:    ${result.error}`);
    }
  }

  console.log(`
Passed ${report.summary.passed}/${report.summary.total} tests.`);

  if (report.summary.failed > 0) {
    process.exitCode = 1;
  }
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});