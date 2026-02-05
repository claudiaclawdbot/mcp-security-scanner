/**
 * Dependencies Module
 * Wraps npm audit for CVE detection, checks outdated packages
 */

import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

const SEVERITY_MAP = {
  critical: 'critical',
  high: 'high',
  moderate: 'medium',
  low: 'low',
  info: 'info'
};

export async function scanDeps(context) {
  const { targetPath, packageJson } = context;
  const findings = [];

  // Run npm audit
  try {
    let auditData;
    try {
      const { stdout } = await execAsync('npm audit --json 2>/dev/null', {
        cwd: targetPath,
        maxBuffer: 10 * 1024 * 1024,
        timeout: 60000
      });
      auditData = JSON.parse(stdout);
    } catch (err) {
      // npm audit returns exit code 1 when vulns found
      if (err.stdout) {
        try { auditData = JSON.parse(err.stdout); } catch {}
      }
    }

    if (auditData?.vulnerabilities) {
      for (const [pkg, vuln] of Object.entries(auditData.vulnerabilities)) {
        const severity = SEVERITY_MAP[vuln.severity] || 'medium';
        
        // Extract CVE from via entries
        let cve = null;
        let title = `${pkg} vulnerability`;
        
        if (Array.isArray(vuln.via)) {
          for (const via of vuln.via) {
            if (typeof via === 'object') {
              cve = via.cve || null;
              title = via.title || title;
              break;
            }
          }
        }

        findings.push({
          module: 'deps',
          id: 'vulnerable-dependency',
          severity,
          package: pkg,
          version: vuln.range || 'unknown',
          title,
          cve,
          message: `${pkg} has a known ${severity} vulnerability${cve ? ` (${cve})` : ''}`,
          remediation: vuln.fixAvailable 
            ? `Fix available: update ${typeof vuln.fixAvailable === 'object' ? vuln.fixAvailable.name : pkg}`
            : 'No automated fix available — review manually',
          file: 'package.json',
          line: 1
        });
      }
    }
  } catch (err) {
    // npm audit not available or failed — not fatal
  }

  // Check for outdated packages
  try {
    let outdated = {};
    try {
      const { stdout } = await execAsync('npm outdated --json 2>/dev/null', {
        cwd: targetPath,
        maxBuffer: 5 * 1024 * 1024,
        timeout: 30000
      });
      outdated = JSON.parse(stdout || '{}');
    } catch (err) {
      if (err.stdout) {
        try { outdated = JSON.parse(err.stdout || '{}'); } catch {}
      }
    }

    for (const [pkg, info] of Object.entries(outdated)) {
      if (info.current !== info.latest) {
        findings.push({
          module: 'deps',
          id: 'outdated-package',
          severity: info.current !== info.wanted ? 'medium' : 'low',
          package: pkg,
          version: info.current,
          message: `${pkg} is outdated: ${info.current} → ${info.latest}`,
          remediation: `Run: npm update ${pkg}`,
          file: 'package.json',
          line: 1
        });
      }
    }
  } catch {
    // Not fatal
  }

  return { module: 'deps', findings };
}
