/**
 * Static Analysis Module
 * Detects dangerous code patterns: shell injection, path traversal, 
 * hardcoded secrets, unsafe deserialization, missing input validation
 */

import { readFile } from 'fs/promises';

const PATTERNS = [
  {
    id: 'shell-injection',
    severity: 'critical',
    pattern: /\b(exec|execSync|spawn|spawnSync)\s*\(\s*(`[^`]*\$\{|['"][^'"]*\+)/g,
    message: 'Potential shell injection: user input in command execution',
    remediation: 'Use execFile() with argument arrays instead of exec() with string interpolation',
    cwe: 'CWE-78'
  },
  {
    id: 'eval-usage',
    severity: 'critical',
    // Match eval/Function calls but not inside strings/comments
    pattern: /(?<!['"`])(?<![/][/*].*)\b(eval|Function)\s*\(/g,
    message: 'Use of eval() or Function() constructor — potential code injection',
    remediation: 'Avoid eval/Function. Use JSON.parse() for data, or a sandboxed interpreter',
    cwe: 'CWE-95'
  },
  {
    id: 'path-traversal',
    severity: 'high',
    pattern: /\b(readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|unlinkSync|rmdir)\s*\(\s*[^)]*(\+\s*(req\.|params|query|body|input|args)|`[^`]*\$\{)/g,
    message: 'Potential path traversal: user input in file system operation',
    remediation: 'Validate and sanitize paths. Use path.resolve() with a safe base directory and verify the result stays within bounds',
    cwe: 'CWE-22'
  },
  {
    id: 'hardcoded-secret',
    severity: 'critical',
    pattern: /(api[_-]?key|apikey|secret|password|token|private[_-]?key|auth)\s*[:=]\s*['"`](?!process\.env)[A-Za-z0-9+/=_\-]{16,}/gi,
    message: 'Hardcoded secret detected',
    remediation: 'Move secrets to environment variables or a secrets manager',
    cwe: 'CWE-798'
  },
  {
    id: 'unsafe-deserialization',
    severity: 'high',
    pattern: /JSON\.parse\s*\(\s*(req\.|params|query|body|input|args|socket|ws)/g,
    message: 'Parsing untrusted JSON input without validation',
    remediation: 'Validate input structure with a schema library (ajv, zod) before or after parsing',
    cwe: 'CWE-502'
  },
  {
    id: 'missing-input-validation',
    severity: 'medium',
    pattern: /\b(req\.body|req\.params|req\.query)\s*\.\s*\w+/g,
    message: 'Direct use of request parameters without visible validation',
    remediation: 'Validate and sanitize all request inputs before use',
    cwe: 'CWE-20'
  },
  {
    id: 'http-not-https',
    severity: 'medium',
    pattern: /['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/g,
    message: 'HTTP URL in production code (should use HTTPS)',
    remediation: 'Use HTTPS for all external connections',
    cwe: 'CWE-319'
  },
  {
    id: 'cors-wildcard',
    severity: 'medium',
    pattern: /['"`]\*['"`]\s*[,)]/g,
    message: 'Possible wildcard CORS — verify this is intentional',
    remediation: 'Restrict CORS to specific origins in production',
    cwe: 'CWE-346'
  }
];

// Simple check: is this position inside a string literal?
function isInString(content, position) {
  let inSingle = false, inDouble = false, inBacktick = false;
  for (let i = 0; i < position; i++) {
    if (content[i] === "'" && content[i-1] !== '\\\\') inSingle = !inSingle;
    if (content[i] === '"' && content[i-1] !== '\\\\') inDouble = !inDouble;
    if (content[i] === '`' && content[i-1] !== '\\\\') inBacktick = !inBacktick;
  }
  return inSingle || inDouble || inBacktick;
}

export async function scanStatic(context) {
  const { files } = context;
  const findings = [];

  for (const file of files) {
    try {
      const content = await readFile(file.path, 'utf8');
      const lines = content.split('\n');

      for (const rule of PATTERNS) {
        // Reset regex state
        rule.pattern.lastIndex = 0;
        let match;

        while ((match = rule.pattern.exec(content)) !== null) {
          // Skip if inside string literal (reduces false positives)
          if (rule.id === 'eval-usage' && isInString(content, match.index)) {
            continue;
          }

          // Find line number
          const beforeMatch = content.substring(0, match.index);
          const lineNum = beforeMatch.split('\n').length;
          const sourceLine = lines[lineNum - 1]?.trim() || '';

          findings.push({
            module: 'static',
            id: rule.id,
            severity: rule.severity,
            file: file.relative,
            line: lineNum,
            message: rule.message,
            remediation: rule.remediation,
            cwe: rule.cwe,
            source: sourceLine.substring(0, 120)
          });
        }
      }
    } catch (err) {
      // Skip files we can't read
    }
  }

  return { module: 'static', findings };
}
