import { lazy } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';

// 页面按路由拆包，避免打开首页时同时解析项目详情、漏洞库、趋势图等全部模块。
const Dashboard = lazy(() => import('./pages/Dashboard'));
const Projects = lazy(() => import('./pages/Projects'));
const NewAuditPage = lazy(() => import('./pages/NewAuditPage'));
const ProjectDetail = lazy(() => import('./pages/ProjectDetail'));
const Vulnerabilities = lazy(() => import('./pages/Vulnerabilities'));
const Monitors = lazy(() => import('./pages/Monitors'));
const Settings = lazy(() => import('./pages/Settings'));
const Recycle = lazy(() => import('./pages/Recycle'));

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/projects" element={<Projects />} />
        <Route path="/projects/new" element={<NewAuditPage />} />
        <Route path="/projects/:id" element={<ProjectDetail />} />
        <Route path="/vulnerabilities" element={<Vulnerabilities />} />
        <Route path="/trends" element={<Navigate to="/dashboard" replace />} />
        <Route path="/monitors" element={<Monitors />} />
        <Route path="/cve" element={<Navigate to="/dashboard" replace />} />
        <Route path="/recycle" element={<Recycle />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
    </Routes>
  );
}
