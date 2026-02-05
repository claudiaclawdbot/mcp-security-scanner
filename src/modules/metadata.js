/**
 * Metadata Module
 * Validates MCP server configuration, package.json hygiene, and security defaults
 */

export async function scanMetadata(context) {
  const { packageJson, manifest } = context;
  const findings = [];

  // Package.json checks
  if (packageJson) {
    if (!packageJson.version) {
      findings.push({
        module: 'meta',
        id: 'missing-version',
        severity: 'low',
        message: 'package.json missing version field',
        remediation: 'Add a semantic version for tracking',
        file: 'package.json',
        line: 1
      });
    }

    if (!packageJson.author && !packageJson.contributors) {
      findings.push({
        module: 'meta',
        id: 'missing-author',
        severity: 'low',
        message: 'No author or maintainer information',
        remediation: 'Add author field for accountability',
        file: 'package.json',
        line: 1
      });
    }

    if (!packageJson.license) {
      findings.push({
        module: 'meta',
        id: 'missing-license',
        severity: 'low',
        message: 'No license specified',
        remediation: 'Add a license field',
        file: 'package.json',
        line: 1
      });
    }

    // Check for risky scripts
    if (packageJson.scripts) {
      const riskyPatterns = ['curl', 'wget', 'eval', 'base64', 'nc ', 'ncat', '/dev/tcp'];
      for (const [name, cmd] of Object.entries(packageJson.scripts)) {
        for (const risky of riskyPatterns) {
          if (cmd.toLowerCase().includes(risky)) {
            findings.push({
              module: 'meta',
              id: 'risky-script',
              severity: 'high',
              message: `Script "${name}" contains suspicious command: ${risky}`,
              remediation: 'Review this script for malicious behavior',
              file: 'package.json',
              line: 1
            });
          }
        }
      }
    }

    // Check for install/preinstall hooks (common supply chain attack vector)
    if (packageJson.scripts?.preinstall || packageJson.scripts?.install || packageJson.scripts?.postinstall) {
      findings.push({
        module: 'meta',
        id: 'install-hook',
        severity: 'medium',
        message: 'Package has install lifecycle hooks — common supply chain attack vector',
        remediation: 'Review install scripts carefully. Consider using --ignore-scripts for untrusted packages',
        file: 'package.json',
        line: 1
      });
    }
  } else {
    findings.push({
      module: 'meta',
      id: 'missing-package-json',
      severity: 'medium',
      message: 'No package.json found',
      remediation: 'Add a package.json with proper metadata',
      file: '.',
      line: 0
    });
  }

  // MCP Manifest checks
  if (manifest) {
    const data = manifest.data;

    if (!data.name) {
      findings.push({
        module: 'meta',
        id: 'manifest-missing-name',
        severity: 'low',
        message: 'MCP manifest missing server name',
        remediation: 'Add a "name" field to your manifest',
        file: manifest.path,
        line: 1
      });
    }

    if (!data.version) {
      findings.push({
        module: 'meta',
        id: 'manifest-missing-version',
        severity: 'low',
        message: 'MCP manifest missing version',
        remediation: 'Add a "version" field',
        file: manifest.path,
        line: 1
      });
    }

    if (!data.capabilities && !data.tools) {
      findings.push({
        module: 'meta',
        id: 'manifest-no-capabilities',
        severity: 'medium',
        message: 'MCP manifest declares no capabilities or tools',
        remediation: 'Declare capabilities for transparency and permission auditing',
        file: manifest.path,
        line: 1
      });
    }

    // Check for overly broad tool descriptions (might indicate hidden functionality)
    if (data.tools && Array.isArray(data.tools)) {
      for (const tool of data.tools) {
        if (!tool.description || tool.description.length < 10) {
          findings.push({
            module: 'meta',
            id: 'vague-tool-description',
            severity: 'low',
            message: `Tool "${tool.name || 'unknown'}" has vague or missing description`,
            remediation: 'Provide clear descriptions of what each tool does',
            file: manifest.path,
            line: 1
          });
        }
      }
    }
  }

  return { module: 'meta', findings };
}
