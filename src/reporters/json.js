/**
 * JSON Reporter
 */

export function jsonReport(results) {
  return JSON.stringify(results, null, 2);
}
