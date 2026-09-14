import type { Severity, ProjectStatus, VerifyStatus } from '../lib/types';
import {
  SEVERITY_LABEL,
  SEVERITY_COLOR,
  STATUS_LABEL,
  STATUS_COLOR,
  phaseStatus,
} from '../lib/format';

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className="badge"
      style={{ background: SEVERITY_COLOR[severity], color: '#fff' }}
    >
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

const RTV_COLOR: Record<string, string> = {
  严重: 'var(--sev-critical)',
  高危: 'var(--sev-high)',
  中危: 'var(--sev-medium)',
  低危: 'var(--sev-low)',
  无: 'var(--sev-info)',
};

/** 红队实战等级徽标（五级：严重/高危/中危/低危/无）。 */
export function RedTeamValueBadge({ value }: { value: string }) {
  const color = RTV_COLOR[value] || 'var(--muted)';
  return (
    <span
      className="badge"
      style={{
        background: `color-mix(in srgb, ${color} 16%, transparent)`,
        color,
      }}
      title="红队实战等级"
    >
      实战 {value}
    </span>
  );
}

export function StatusBadge({ status }: { status: ProjectStatus }) {
  const color = STATUS_COLOR[status];
  return (
    <span
      className="badge"
      style={{
        background: `color-mix(in srgb, ${color} 16%, transparent)`,
        color,
      }}
    >
      <span
        style={{
          width: 6,
          height: 6,
          borderRadius: '50%',
          background: color,
          display: 'inline-block',
        }}
      />
      {STATUS_LABEL[status]}
    </span>
  );
}

/** 贯穿"代码审计 → 靶机验证"全流程的综合状态徽标。 */
export function PhaseBadge({
  status,
  verifyStatus,
}: {
  status: ProjectStatus;
  verifyStatus: VerifyStatus;
}) {
  const { label, color } = phaseStatus(status, verifyStatus);
  const active = label.endsWith('中');
  return (
    <span
      className="badge"
      style={{
        background: `color-mix(in srgb, ${color} 16%, transparent)`,
        color,
      }}
    >
      <span
        className={active ? 'badge-dot-pulse' : ''}
        style={{
          width: 6,
          height: 6,
          borderRadius: '50%',
          background: color,
          display: 'inline-block',
        }}
      />
      {label}
    </span>
  );
}
