import type { Project } from '../lib/types';
import './NextStepModal.css';

/**
 * 「继续 → 下一步」选择框：仅代码审计的项目审计完成后，点「继续」时弹出。
 */
export default function NextStepModal({
  project,
  onClose,
  onChoose,
}: {
  project: Project;
  onClose: () => void;
  onChoose: () => void;
}) {
  return (
    <div className="nextstep-overlay" onClick={onClose}>
      <div className="nextstep-modal" onClick={(e) => e.stopPropagation()}>
        <h3>代码审计已完成</h3>
        <p className="nextstep-sub">
          「{project.system_name || project.project_name}」的代码审计已完成。请选择下一步：
          进入靶机验证，或取消（保持在「代码审计完成」）。
        </p>
        <div className="nextstep-actions">
          <button className="btn btn-primary" onClick={onChoose}>
            进入靶机验证
          </button>
          <button className="btn btn-ghost" onClick={onClose}>
            取消
          </button>
        </div>
      </div>
    </div>
  );
}
