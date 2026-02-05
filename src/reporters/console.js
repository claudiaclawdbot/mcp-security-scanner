/**
 * Console Reporter - Pretty terminal output
 */

const SEVERITY_ICONS = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  info: '⚪'
};

export function consoleReport(results, options = {}) {
  const { target, summary, findings, duration, errors } = results;

  console.log('');
  console.log('━'.repeat(60));
  console.log(`  MCP Security Scanner v${results.scannerVersion}`);
  console.log(`  Scan ID: ${results.scanId}`);
  console.log('━'.repeat(60));
  console.log('');
  console.log(`  Target:   ${target.serverName} v${target.serverVersion}`);
  console.log(`  Path:     ${target.path}`);
  console.log(`  Files:    ${target.filesScanned}`);
  console.log(`  Duration: ${duration}ms`);
  console.log('');

  // Summary
  console.log('━'.repeat(60));
  console.log('  SUMMARY');
  console.log('━'.repeat(60));
  console.log('');
  console.log(`  Risk Score: ${summary.riskScore}/100 (${summary.riskLevel.toUpperCase()})`);
  console.log('');
  console.log(`  ${SEVERITY_ICONS.critical} Critical: ${summary.bySeverity.critical}`);
  console.log(`  ${SEVERITY_ICONS.high} High:     ${summary.bySeverity.high}`);
  console.log(`  ${SEVERITY_ICONS.medium} Medium:   ${summary.bySeverity.medium}`);
  console.log(`  ${SEVERITY_ICONS.low} Low:      ${summary.bySeverity.low}`);
  console.log(`  ${SEVERITY_ICONS.info} Info:     ${summary.bySeverity.info}`);
  console.log('');

  if (findings.length === 0) {
    console.log('  ✅ No security issues found!');
    console.log('');
    return;
  }

  // Findings
  console.log('━'.repeat(60));
  console.log('  FINDINGS');
  console.log('━'.repeat(60));

  for (const f of findings) {
    const icon = SEVERITY_ICONS[f.severity] || '❓';
    const sev = f.severity.toUpperCase();
    console.log('');
    console.log(`  ${icon} ${sev}: ${f.message}`);
    if (f.file) console.log(`     File: ${f.file}${f.line ? ':' + f.line : ''}`);
    if (f.source) console.log(`     Code: ${f.source}`);
    if (f.cwe) console.log(`     CWE:  ${f.cwe}`);
    if (f.cve) console.log(`     CVE:  ${f.cve}`);
    if (f.remediation) console.log(`     Fix:  ${f.remediation}`);
    console.log('  ' + '─'.repeat(56));
  }

  if (errors.length > 0) {
    console.log('');
    console.log('  ⚠️  ERRORS:');
    for (const e of errors) {
      console.log(`     ${e.module}: ${e.error}`);
    }
  }

  console.log('');
}
