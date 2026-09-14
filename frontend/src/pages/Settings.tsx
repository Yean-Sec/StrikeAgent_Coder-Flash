import { useEffect, useState } from 'react';
import { api } from '../lib/api';
import type { Settings as SettingsType } from '../lib/types';
import './Settings.css';

const DEFAULT_COMMAND =
  'pi --mode json --no-session --no-context-files --provider anthropic {prompt}';
const DEFAULT_AUDIT_PROMPT =
  '你是代码安全审计员。只做静态发现并落盘 JSON，不要去重、不要代码级验证、不要搭靶机。';
const DEFAULT_VERIFY_PROMPT = `针对已发现的漏洞，在已搭建的本地靶机上做真实利用验证与取证。
分步：先确认 Docker 靶机可达并登录；再逐条验证单漏洞；最后尝试无权限/低权限到 RCE 的组合利用。禁止只读源码就判成功。组合链不要从管理员权限起步。`;

export default function Settings() {
  const [s, setS] = useState<SettingsType | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    api.getSettings().then(setS);
  }, []);

  const update = (k: keyof SettingsType, v: string) =>
    setS((prev) => (prev ? { ...prev, [k]: v } : prev));

  const save = async () => {
    if (!s) return;
    await api.saveSettings(s);
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  if (!s) return <div className="loading">加载中…</div>;

  return (
    <div className="settings-page">
      <div className="page-head">
        <h1>设置</h1>
        <p>配置 Pi 启动命令、默认提示词与运行参数</p>
      </div>

      <div className="card setting-card">
        <h3>漏洞审计提示词</h3>
        <p className="muted">
          新建项目时自动执行的<strong>漏洞审计</strong>指令。后端按所选语言并发拉起多路专项审计进程，只做静态发现。系统会在其后自动追加审计目标与结构化输出要求。
        </p>
        <textarea
          className="textarea"
          rows={3}
          value={s.audit_prompt}
          onChange={(e) => update('audit_prompt', e.target.value)}
        />
        <button className="link-reset" onClick={() => update('audit_prompt', DEFAULT_AUDIT_PROMPT)}>
          恢复默认
        </button>
      </div>

      <div className="card setting-card">
        <h3>漏洞验证提示词</h3>
        <p className="muted">
          靶机验证阶段执行的指令（自动或手动发起均使用）。验证会重新起一个会话、读取已发现的漏洞，
          先确认 Docker 靶机可达，再逐条验证单漏洞，最后做组合利用。
        </p>
        <textarea
          className="textarea"
          rows={6}
          value={s.verify_prompt}
          onChange={(e) => update('verify_prompt', e.target.value)}
        />
        <button className="link-reset" onClick={() => update('verify_prompt', DEFAULT_VERIFY_PROMPT)}>
          恢复默认
        </button>
      </div>

      <div className="card setting-card">
        <h3>默认启动命令</h3>
        <p className="muted">
          用于启动 Pi 的命令模板。占位符：
          <code>{'{prompt}'}</code> 提示词。工作区作为进程 cwd，无需 <code>--add-dir</code>。
          JSON Schema 由后端写入提示词末尾，不必作为 CLI 参数。超长提示会改写为 <code>@文件</code>。
        </p>
        <textarea
          className="textarea"
          rows={4}
          value={s.default_command}
          onChange={(e) => update('default_command', e.target.value)}
        />
        <button
          className="link-reset"
          onClick={() => update('default_command', DEFAULT_COMMAND)}
        >
          恢复默认
        </button>
      </div>

      <div className="card setting-card">
        <h3>运行参数</h3>
        <div className="setting-row">
          <div className="setting-field">
            <label>代码审计并发数</label>
            <input
              className="input"
              type="number"
              min={1}
              max={10}
              value={s.max_concurrency}
              onChange={(e) => update('max_concurrency', e.target.value)}
            />
            <span className="field-hint">
              同时运行的代码审计 Pi 主控数（默认 5，最多 10）。审计内的去重/代码级验证/评级占用同一审计槽，不额外占验证槽。
            </span>
          </div>
          <div className="setting-field">
            <label>远程验证并发数</label>
            <input
              className="input"
              type="number"
              min={1}
              max={12}
              value={s.remote_verify_concurrency || s.verify_global_concurrency}
              onChange={(e) => update('remote_verify_concurrency', e.target.value)}
            />
            <span className="field-hint">
              同时运行的靶机验证 Pi 主控数（默认 5，与代码审计槽独立计数）。超出则排队。审计并行时靶机搭建另受 env_concurrency 约束。
            </span>
          </div>
          <div className="setting-field">
            <label>远程验证突发并发数</label>
            <input
              className="input"
              type="number"
              min={1}
              max={12}
              value={s.remote_verify_burst_concurrency || '5'}
              onChange={(e) => update('remote_verify_burst_concurrency', e.target.value)}
            />
            <span className="field-hint">
              当全部项目代码审计已结束、队列里只剩靶机验证时，临时抬高的并发上限（默认 5）。含靶机搭建与远程验证主控；有审计在跑时仍用上面的「远程验证并发数」（现默认亦为 5）。
            </span>
          </div>
          <div className="setting-field">
            <label>保护 Web 服务资源</label>
            <select
              className="input"
              value={s.protect_web_resources ?? '1'}
              onChange={(e) => update('protect_web_resources', e.target.value)}
            >
              <option value="1">开启（推荐，主控常态最多 3 个）</option>
              <option value="0">关闭（完全按并发配置运行）</option>
            </select>
            <span className="field-hint">
              开启后会为 Web 页面预留内存和事件循环；资源紧张时自动暂缓启动新任务，不中断已运行任务。
            </span>
          </div>
          <div className="setting-field">
            <label>启动时自动续跑中断任务</label>
            <select
              className="input"
              value={s.auto_resume_orphans_on_startup ?? '0'}
              onChange={(e) => update('auto_resume_orphans_on_startup', e.target.value)}
            >
              <option value="0">关闭（推荐：中断任务仅标为暂停）</option>
              <option value="1">开启（重启后自动 spawn Pi 续跑）</option>
            </select>
            <span className="field-hint">
              关闭后，杀进程或重启后端不会再批量拉起 Pi；需要续跑时在审计列表点「继续」，或临时开启本项。
            </span>
          </div>
          <div className="setting-field">
            <label>Pi 任务总闸</label>
            <select
              className="input"
              value={s.claude_jobs_enabled ?? '1'}
              onChange={(e) => update('claude_jobs_enabled', e.target.value)}
            >
              <option value="1">开启（允许审计/验证/监控触发）</option>
              <option value="0">关闭（停摆：拒绝一切 Pi 入队与 spawn）</option>
            </select>
            <span className="field-hint">
              关闭后会立即暂停并杀掉所有运行中任务；批量继续、监控新版本、新建审计都不会再拉起 Pi，直到重新开启。
            </span>
          </div>
        </div>
        <div className="setting-row">
          <div className="setting-field">
            <label>监控轮询间隔（分钟）</label>
            <input
              className="input"
              type="number"
              min={1}
              value={s.poll_interval}
              onChange={(e) => update('poll_interval', e.target.value)}
            />
            <span className="field-hint">监控模式新建时的默认间隔</span>
          </div>
        </div>
        <div className="setting-row">
          <div className="setting-field">
            <label>单阶段最长运行时间（分钟）</label>
            <input
              className="input"
              type="number"
              min={5}
              value={s.stage_timeout_min}
              onChange={(e) => update('stage_timeout_min', e.target.value)}
            />
            <span className="field-hint">审计/验证单阶段超过此时长将自动终止并标记失败</span>
          </div>
          <div className="setting-field">
            <label>空闲超时（分钟）</label>
            <input
              className="input"
              type="number"
              min={5}
              value={s.idle_timeout_min}
              onChange={(e) => update('idle_timeout_min', e.target.value)}
            />
            <span className="field-hint">连续无输出超过此时长视为卡死，自动终止任务</span>
          </div>
          <div className="setting-field">
            <label>单漏洞总时限（分钟）</label>
            <input
              className="input"
              type="number"
              min={5}
              value={s.single_verify_timeout_min ?? '15'}
              onChange={(e) => update('single_verify_timeout_min', e.target.value)}
            />
            <span className="field-hint">包含源码准备、靶机拉起和远程实测；默认 15 分钟</span>
          </div>
          <div className="setting-field">
            <label>单漏洞空闲时限（分钟）</label>
            <input
              className="input"
              type="number"
              min={3}
              value={s.single_verify_idle_timeout_min ?? '5'}
              onChange={(e) => update('single_verify_idle_timeout_min', e.target.value)}
            />
            <span className="field-hint">连续无输出即终止，保留已有证据并标记为超时受限</span>
          </div>
          <div className="setting-field">
            <label>结果收尾宽限（分钟）</label>
            <input
              className="input"
              type="number"
              min={1}
              value={s.settle_timeout_min}
              onChange={(e) => update('settle_timeout_min', e.target.value)}
            />
            <span className="field-hint">已拿到完整结果后，进程仍不退出则等待此时长主动收尾（视为正常完成）</span>
          </div>
          <div className="setting-field">
            <label>精简验证提示词（省 token）</label>
            <select
              className="input"
              value={s.lean_verify_prompt}
              onChange={(e) => update('lean_verify_prompt', e.target.value)}
            >
              <option value="0">关闭（现状）</option>
              <option value="1">开启（子智能体按 index 读盘 + 免冗余兜底输出）</option>
            </select>
            <span className="field-hint">开启后主控不再把候选原文逐字塞进派发指令（子智能体自行读 input.json），且落盘成功后不再重复输出一份 StructuredOutput</span>
          </div>
          <div className="setting-field">
            <label>去重保留「多利用面」</label>
            <select
              className="input"
              value={s.dedup_keep_variants ?? '1'}
              onChange={(e) => update('dedup_keep_variants', e.target.value)}
            >
              <option value="1">开启（同点多面各自保留、逐面验证）</option>
              <option value="0">关闭（同点即合并成一条，旧行为）</option>
            </select>
            <span className="field-hint">
              开启后 AI 去重只删「纯措辞重复」；同一代码点的不同利用面（不同触发条件/参数/漏洞类型）各自保留为独立漏洞并归簇（1 点 N 面），代码级与远程验证逐面覆盖，避免漏面。
            </span>
          </div>
          <div className="setting-field">
            <label>AI 去重候选门槛（省 token）</label>
            <input
              className="input"
              type="number"
              min={0}
              value={s.ai_dedup_min_candidates}
              onChange={(e) => update('ai_dedup_min_candidates', e.target.value)}
            />
            <span className="field-hint">候选数低于此值时跳过整个 AI 语义去重环节（机械去重仍生效）。0=始终跑 AI 去重（现状）</span>
          </div>
          <div className="setting-field">
            <label>核验每路条数</label>
            <input
              className="input"
              type="number"
              min={1}
              max={50}
              value={s.regrade_batch_size || '10'}
              onChange={(e) => update('regrade_batch_size', e.target.value)}
            />
            <span className="field-hint">
              AI 智能去重、代码级验证、红队二次评级共用：每个工人处理这么多条（默认 10）。去重会先按文件装箱，同一文件不拆组。
            </span>
          </div>
          <div className="setting-field">
            <label>核验并发路数</label>
            <input
              className="input"
              type="number"
              min={1}
              max={10}
              value={s.regrade_concurrency || '10'}
              onChange={(e) => update('regrade_concurrency', e.target.value)}
            />
            <span className="field-hint">
              上述三个环节共用：最多同时拉起这么多路 Pi 工人（默认 10，封顶 10）。默认 10 路 × 每路 10 条 = 一轮最多 100 个；超出排队下一组。这是真实进程并发。
            </span>
          </div>
          <div className="setting-field">
            <label>验证环节专用命令（省 token · 模型分级）</label>
            <input
              className="input mono"
              placeholder="留空则沿用上方默认启动命令"
              value={s.verify_command}
              onChange={(e) => update('verify_command', e.target.value)}
            />
            <span className="field-hint">仅用于代码验证层（去重/代码级验证/二次评级）。填写后可把这些核验任务路由到更便宜的模型（如换 --model 到 haiku 档），占位符同默认命令（{'{prompt}'}）；靶机验证不受影响</span>
          </div>
        </div>
        <div className="setting-field">
          <label>GitHub Token（可选）</label>
          <input
            className="input"
            type="password"
            placeholder="用于克隆私有仓库与提升 Releases 轮询频率"
            value={s.github_token}
            onChange={(e) => update('github_token', e.target.value)}
          />
        </div>
        <div className="setting-field">
          <label>Pi 可执行文件路径（可选）</label>
          <input
            className="input mono"
            placeholder="留空则自动探测全局安装的 pi"
            value={s.claude_path}
            onChange={(e) => update('claude_path', e.target.value)}
          />
        </div>
      </div>

      <div className="settings-foot">
        <button className="btn btn-primary" onClick={save}>
          保存设置
        </button>
        {saved && <span className="saved-msg">✓ 已保存</span>}
      </div>
    </div>
  );
}
