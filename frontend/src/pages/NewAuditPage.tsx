import { useNavigate } from 'react-router-dom';
import NewAudit from '../components/NewAudit';
import './Projects.css';

export default function NewAuditPage() {
  const navigate = useNavigate();
  return (
    <div className="projects-page">
      <button type="button" className="back-link" onClick={() => navigate('/projects')}>
        <span className="back-link-arrow" aria-hidden="true">
          ←
        </span>
        返回审计列表
      </button>
      <div className="page-head">
        <h1>新建审计</h1>
        <p>上传压缩包或填写 GitHub 地址，发起新的代码安全审计</p>
      </div>
      <NewAudit onCreated={() => navigate('/projects')} />
    </div>
  );
}
