/**
 * Permissions Module
 * Analyzes MCP capability declarations vs actual code usage
 * Detects undeclared file/network/process access
 */

import { readFile } from 'fs/promises';

// Patterns that indicate specific capability usage
const CAPABILITY_PATTERNS = {
  'fs:read': [
    /\breadFile\b/g, /\breadFileSync\b/g, /\bcreateReadStream\b/g,
    /\breaddir\b/g, /\breaddirSync\b/g, /\bstat\b/g, /\bstatSync\b/g
  ],
  'fs:write': [
    /\bwriteFile\b/g, /\bwriteFileSync\b/g, /\bcreateWriteStream\b/g,
    /\bmkdir\b/g, /\bmkdirSync\b/g, /\bunlink\b/g, /\bunlinkSync\b/g,
    /\brm\b/g, /\brmSync\b/g
  ],
  'network:http': [
    /\bfetch\s*\(/g, /\baxios\b/g, /\bhttps?\.\w+/g,
    /\bhttp\.request\b/g, /\bhttp\.get\b/g, /\bnew\s+URL\b/g
  ],
  'network:ws': [
    /\bnew\s+WebSocket\b/g, /\bWebSocketServer\b/g, /\bws\.\w+/g
  ],
  'process:exec': [
    /\bexec\b/g, /\bexecSync\b/g, /\bspawn\b/g, /\bspawnSync\b/g,
    /\bchild_process\b/g, /\bexecFile\b/g
  ],
  'process:env': [
    /\bprocess\.env\b/g
  ],
  'crypto': [
    /\bcrypto\.\w+/g, /\bcreateHash\b/g, /\bcreateHmac\b/g,
    /\brandomBytes\b/g
  ]
};

export async function scanPermissions(context) {
  const { files, manifest } = context;
  const findings = [];

  // Get declared capabilities from manifest
  const declaredCapabilities = new Set();
  if (manifest?.data?.capabilities) {
    if (Array.isArray(manifest.data.capabilities)) {
      manifest.data.capabilities.forEach(c => declaredCapabilities.add(c));
    } else if (typeof manifest.data.capabilities === 'object') {
      Object.keys(manifest.data.capabilities).forEach(c => declaredCapabilities.add(c));
    }
  }

  // Scan files for actual capability usage
  const actualUsage = {};

  for (const file of files) {
    try {
      const content = await readFile(file.path, 'utf8');

      for (const [capability, patterns] of Object.entries(CAPABILITY_PATTERNS)) {
        for (const pattern of patterns) {
          pattern.lastIndex = 0;
          const match = pattern.exec(content);
          if (match) {
            if (!actualUsage[capability]) actualUsage[capability] = [];
            const beforeMatch = content.substring(0, match.index);
            const lineNum = beforeMatch.split('\n').length;
            actualUsage[capability].push({
              file: file.relative,
              line: lineNum,
              match: match[0]
            });
          }
        }
      }
    } catch {
      // Skip unreadable files
    }
  }

  // Compare declared vs actual
  if (manifest) {
    // Report undeclared capabilities
    for (const [capability, usages] of Object.entries(actualUsage)) {
      if (!declaredCapabilities.has(capability)) {
        const first = usages[0];
        findings.push({
          module: 'perms',
          id: 'undeclared-capability',
          severity: capability.startsWith('process:exec') ? 'high' : 'medium',
          capability,
          message: `Uses ${capability} without declaring it in manifest (${usages.length} occurrence${usages.length > 1 ? 's' : ''})`,
          remediation: `Add "${capability}" to capabilities in ${manifest.path}`,
          file: first.file,
          line: first.line,
          occurrences: usages.length
        });
      }
    }

    // Report declared but unused capabilities (info level)
    for (const cap of declaredCapabilities) {
      if (!actualUsage[cap]) {
        findings.push({
          module: 'perms',
          id: 'unused-capability',
          severity: 'info',
          capability: cap,
          message: `Capability "${cap}" declared but not used in source code`,
          remediation: `Remove "${cap}" from capabilities if not needed (principle of least privilege)`,
          file: manifest.path,
          line: 1
        });
      }
    }
  } else {
    // No manifest found — report dangerous capabilities as warnings
    for (const [capability, usages] of Object.entries(actualUsage)) {
      if (['process:exec', 'fs:write', 'network:http'].includes(capability)) {
        const first = usages[0];
        findings.push({
          module: 'perms',
          id: 'no-manifest-dangerous-cap',
          severity: 'low',
          capability,
          message: `No MCP manifest found, but code uses ${capability} (${usages.length} times)`,
          remediation: 'Add a server.json manifest declaring capabilities for transparency',
          file: first.file,
          line: first.line
        });
      }
    }
  }

  return { module: 'perms', findings };
}
