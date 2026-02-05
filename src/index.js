/**
 * MCP Security Scanner - Core Orchestrator
 * Discovers files, runs scan modules in parallel, aggregates results
 */

import { readdir, readFile, stat, access } from 'fs/promises';
import { join, extname, relative } from 'path';
import { scanStatic } from './modules/static-analysis.js';
import { scanDeps } from './modules/dependencies.js';
import { scanPermissions } from './modules/permissions.js';
import { scanMetadata } from './modules/metadata.js';
import { calculateRiskScore, getRiskLevel } from './utils/scoring.js';

const SOURCE_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx']);

/**
 * Recursively discover source files
 */
async function discoverFiles(dir, files = [], baseDir = dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    
    // Skip node_modules, .git, dist, build
    if (entry.isDirectory()) {
      if (['node_modules', '.git', 'dist', 'build', 'coverage', '.next'].includes(entry.name)) continue;
      await discoverFiles(fullPath, files, baseDir);
    } else if (entry.isFile() && SOURCE_EXTENSIONS.has(extname(entry.name))) {
      files.push({
        path: fullPath,
        relative: relative(baseDir, fullPath),
        name: entry.name
      });
    }
  }
  
  return files;
}

/**
 * Try to find and parse MCP server manifest
 */
async function findManifest(targetPath) {
  const candidates = ['server.json', 'mcp.json', 'manifest.json', '.mcp/config.json'];
  
  for (const candidate of candidates) {
    try {
      const content = await readFile(join(targetPath, candidate), 'utf8');
      return { path: candidate, data: JSON.parse(content) };
    } catch {
      continue;
    }
  }
  return null;
}

/**
 * Try to parse package.json
 */
async function findPackageJson(targetPath) {
  try {
    const content = await readFile(join(targetPath, 'package.json'), 'utf8');
    return JSON.parse(content);
  } catch {
    return null;
  }
}

/**
 * Main scanner orchestrator
 */
export async function scanner(targetPath, options = {}) {
  const { modules = ['static', 'deps', 'perms', 'meta'], verbose = false } = options;
  
  const startTime = Date.now();
  
  // Discovery phase
  if (verbose) console.log('Discovering files...');
  const [files, manifest, packageJson] = await Promise.all([
    discoverFiles(targetPath),
    findManifest(targetPath),
    findPackageJson(targetPath)
  ]);
  
  if (verbose) console.log(`Found ${files.length} source files`);

  const context = { targetPath, files, manifest, packageJson };
  
  // Run scan modules in parallel
  const scanTasks = [];
  
  if (modules.includes('static')) {
    scanTasks.push(
      scanStatic(context).catch(err => ({ module: 'static', error: err.message, findings: [] }))
    );
  }
  if (modules.includes('deps') && packageJson) {
    scanTasks.push(
      scanDeps(context).catch(err => ({ module: 'deps', error: err.message, findings: [] }))
    );
  }
  if (modules.includes('perms')) {
    scanTasks.push(
      scanPermissions(context).catch(err => ({ module: 'perms', error: err.message, findings: [] }))
    );
  }
  if (modules.includes('meta')) {
    scanTasks.push(
      scanMetadata(context).catch(err => ({ module: 'meta', error: err.message, findings: [] }))
    );
  }

  const moduleResults = await Promise.all(scanTasks);
  
  // Aggregate findings
  const allFindings = [];
  const modulesSummary = {};
  const errors = [];
  
  for (const result of moduleResults) {
    if (result.error) {
      errors.push({ module: result.module, error: result.error });
    }
    modulesSummary[result.module] = {
      findings: result.findings?.length || 0,
      error: result.error || null
    };
    if (result.findings) {
      allFindings.push(...result.findings);
    }
  }

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  allFindings.sort((a, b) => (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5));

  // Calculate risk score
  const riskScore = calculateRiskScore(allFindings);
  const riskLevel = getRiskLevel(riskScore);

  // Build summary
  const summary = {
    riskScore,
    riskLevel,
    totalFindings: allFindings.length,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  };
  
  for (const f of allFindings) {
    summary.bySeverity[f.severity] = (summary.bySeverity[f.severity] || 0) + 1;
  }

  return {
    scanId: crypto.randomUUID().slice(0, 8),
    timestamp: new Date().toISOString(),
    scannerVersion: '1.0.0',
    target: {
      path: targetPath,
      serverName: packageJson?.name || manifest?.data?.name || 'unknown',
      serverVersion: packageJson?.version || manifest?.data?.version || 'unknown',
      filesScanned: files.length
    },
    summary,
    modules: modulesSummary,
    findings: allFindings,
    errors,
    duration: Date.now() - startTime
  };
}

export default scanner;
