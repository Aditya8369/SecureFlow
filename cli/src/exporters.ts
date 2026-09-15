/**
 * Alternative Export Formatters for SecureFlow CLI (#811)
 *
 * Provides CSV and HTML report generation for stakeholders who do not use
 * SARIF viewers. Both formatters are zero-dependency, using pure string
 * templates to keep the CLI lightweight.
 *
 * PDF generation was intentionally not added because it would introduce a
 * heavyweight PDF-generation dependency (e.g. pdfkit, puppeteer). HTML
 * provides a portable report that users can directly print/save as PDF
 * from any browser.
 */

// Added `type` prefix for verbatimModuleSyntax compliance
import type { FileScanResult } from "./scanner.js";

// ---------------------------------------------------------------------------
// Escape helpers
// ---------------------------------------------------------------------------

/**
 * Escapes a value for safe embedding in a CSV cell per RFC 4180.
 *
 * - If the value contains a comma, double-quote, or newline, the entire value
 *   is wrapped in double-quotes.
 * - Any internal double-quotes are doubled (`"` → `""`).
 */
export function escapeCsv(value: string): string {
  if (value.includes('"') || value.includes(",") || value.includes("\n") || value.includes("\r")) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

/**
 * Escapes special HTML characters to prevent XSS when embedding untrusted
 * content (e.g. source code snippets) in generated HTML reports.
 */
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ---------------------------------------------------------------------------
// CSV formatter
// ---------------------------------------------------------------------------

const CSV_HEADERS = "File,Line,Violation,Reason";

/**
 * Formats scan results as a CSV string.
 *
 * Columns: `File`, `Line`, `Violation`, `Reason`
 *
 * All cell values are escaped per RFC 4180 so embedded commas, quotes, and
 * newlines do not corrupt the output.
 */
export function formatCsv(results: FileScanResult[]): string {
  const rows: string[] = [CSV_HEADERS];

  for (const file of results) {
    for (const v of file.violations) {
      rows.push(
        [escapeCsv(file.path), String(v.line), escapeCsv(v.text), escapeCsv(v.reason)].join(","),
      );
    }
  }

  return rows.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// HTML formatter
// ---------------------------------------------------------------------------

/**
 * Generates a self-contained, styled HTML report of scan results.
 *
 * The document includes inline CSS so it can be opened directly in a browser
 * or printed / saved as PDF without any external assets.
 *
 * All untrusted content (file paths, source snippets, reasons) is
 * HTML-escaped to prevent XSS.
 */
export function formatHtml(results: FileScanResult[]): string {
  const violations: { path: string; line: number; text: string; reason: string }[] = [];

  for (const file of results) {
    for (const v of file.violations) {
      violations.push({ path: file.path, line: v.line, text: v.text, reason: v.reason });
    }
  }

  const tableRows =
    violations.length > 0
      ? violations
          .map(
            (v) =>
              `        <tr>
          <td>${escapeHtml(v.path)}</td>
          <td>${v.line}</td>
          <td><code>${escapeHtml(v.text)}</code></td>
          <td>${escapeHtml(v.reason)}</td>
        </tr>`,
          )
          .join("\n")
      : `        <tr><td colspan="4" class="empty">No violations detected.</td></tr>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureFlow Scan Report</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: #f6f8fa;
      color: #24292f;
      padding: 2rem;
      line-height: 1.5;
    }
    h1 {
      font-size: 1.5rem;
      margin-bottom: 0.25rem;
    }
    .meta {
      color: #57606a;
      font-size: 0.875rem;
      margin-bottom: 1.5rem;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      background: #ffffff;
      border: 1px solid #d0d7de;
      border-radius: 6px;
      overflow: hidden;
    }
    th, td {
      text-align: left;
      padding: 0.5rem 0.75rem;
      border-bottom: 1px solid #d0d7de;
    }
    th {
      background: #f6f8fa;
      font-weight: 600;
      font-size: 0.875rem;
    }
    td code {
      background: #f0f3f6;
      padding: 0.125rem 0.375rem;
      border-radius: 3px;
      font-size: 0.8125rem;
    }
    tr:last-child td { border-bottom: none; }
    .empty {
      text-align: center;
      color: #57606a;
      padding: 1.5rem;
    }
    .summary {
      margin-top: 1rem;
      font-size: 0.875rem;
      color: #57606a;
    }
    @media print {
      body { background: #fff; padding: 0; }
    }
  </style>
</head>
<body>
  <h1>SecureFlow Scan Report</h1>
  <p class="meta">Generated by SecureFlow CLI</p>
  <table>
    <thead>
      <tr>
        <th>File</th>
        <th>Line</th>
        <th>Violation</th>
        <th>Reason</th>
      </tr>
    </thead>
    <tbody>
${tableRows}
    </tbody>
  </table>
  <p class="summary">${violations.length} violation${violations.length === 1 ? "" : "s"} found.</p>
</body>
</html>
`;
}
