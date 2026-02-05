#!/usr/bin/env node

import { program } from 'commander';
import { resolve } from 'path';
import { scanner } from '../src/index.js';
import { consoleReport } from '../src/reporters/console.js';
import { jsonReport } from '../src/reporters/json.js';
import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const pkg = JSON.parse(await readFile(join(__dirname, '..', 'package.json'), 'utf8'));

program
  .name('mcp-scan')
  .version(pkg.version)
  .description('Security scanner for MCP (Model Context Protocol) servers')
  .argument('[target]', 'Directory to scan', '.')
  .option('-o, --output <path>', 'Output JSON report to file')
  .option('-f, --format <type>', 'Output format: console|json|all', 'console')
  .option('-s, --severity <level>', 'Minimum severity: low|medium|high|critical', 'low')
  .option('-m, --modules <list>', 'Modules to run (comma-separated): static,deps,perms,meta', 'static,deps,perms,meta')
  .option('--ci', 'CI mode: exit 1 if findings above threshold')
  .option('--threshold <level>', 'CI threshold severity', 'high')
  .option('--no-color', 'Disable colored output')
  .option('--include-tests', 'Include test files in scan')
  .option('--verbose', 'Show detailed progress')
  .action(async (target, opts) => {
    const targetPath = resolve(target);
    const modules = opts.modules.split(',').map(m => m.trim());
    
    const severityOrder = ['info', 'low', 'medium', 'high', 'critical'];
    const minSeverityIdx = severityOrder.indexOf(opts.severity);

    try {
      const results = await scanner(targetPath, {
        modules,
        verbose: opts.verbose,
        includeTests: opts.includeTests,
        minSeverity: opts.severity
      });

      // Filter by severity
      if (minSeverityIdx > 0) {
        results.findings = results.findings.filter(f => 
          severityOrder.indexOf(f.severity) >= minSeverityIdx
        );
      }

      // Output
      if (opts.format === 'console' || opts.format === 'all') {
        consoleReport(results, { color: opts.color !== false });
      }

      if (opts.format === 'json' || opts.format === 'all' || opts.output) {
        const json = jsonReport(results);
        if (opts.output) {
          const { writeFile } = await import('fs/promises');
          await writeFile(opts.output, json);
          console.log(`\nJSON report saved to: ${opts.output}`);
        }
        if (opts.format === 'json') {
          console.log(json);
        }
      }

      // CI mode exit code
      if (opts.ci) {
        const thresholdIdx = severityOrder.indexOf(opts.threshold);
        const hasFailures = results.findings.some(f => 
          severityOrder.indexOf(f.severity) >= thresholdIdx
        );
        process.exit(hasFailures ? 1 : 0);
      }

    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(2);
    }
  });

program.parse();
