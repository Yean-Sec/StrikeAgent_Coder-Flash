/** CVE / GitHub 报送共用的条目收集逻辑。 */
import db from './db';
import { buildVulnLibrary } from './cve';
import { normalizeTaintChain } from './util';

export interface ReportSubmitItem {
  kind: 'vuln' | 'chain';
  ref: string;
}

function sanitizeReportRow(row: Record<string, unknown>): Record<string, unknown> {
  const next = { ...row };
  if ('taint_chain' in next) next.taint_chain = normalizeTaintChain(next.taint_chain);
  return next;
}

export function collectReportItems(items: ReportSubmitItem[]): any[] {
  const lib = buildVulnLibrary({ pageSize: 10000 });
  const vulnById = new Map(lib.vulns.map((v) => [v.id, v]));
  const chainByRef = new Map(lib.chains.map((c) => [c.ref, c]));
  const out: any[] = [];
  for (const it of items) {
    if (it.kind === 'vuln' && vulnById.has(it.ref)) {
      const v = vulnById.get(it.ref)!;
      const proj = db.prepare('SELECT source_type, source_ref FROM projects WHERE id = ?').get(v.project_id) as
        | { source_type: string; source_ref: string }
        | undefined;
      out.push(
        sanitizeReportRow({
          kind: 'vuln',
          ...v,
          source_type: proj?.source_type,
          source_ref: proj?.source_ref,
        })
      );
    } else if (it.kind === 'chain' && chainByRef.has(it.ref)) {
      const c = chainByRef.get(it.ref)!;
      const proj = db.prepare('SELECT source_type, source_ref FROM projects WHERE id = ?').get(c.project_id) as
        | { source_type: string; source_ref: string }
        | undefined;
      out.push(
        sanitizeReportRow({
          kind: 'chain',
          ...c,
          source_type: proj?.source_type,
          source_ref: proj?.source_ref,
        })
      );
    }
  }
  return out;
}
