import assert from 'node:assert/strict';
import test from 'node:test';
import { applySeverityPolicy } from './severityPolicy';

test('纯 OOM、泄漏和 DoS 封顶为 low', () => {
  const cases = [
    '请求体无大小限制导致内存耗尽 OOM',
    '后台任务连接泄漏导致连接池耗尽',
    '正则灾难性回溯导致 ReDoS',
    '递归无深度限制导致栈溢出拒绝服务',
  ];
  for (const title of cases) {
    const result = applySeverityPolicy({ title, severity: 'high' });
    assert.equal(result.severity, 'low', title);
    assert.equal(result.ruleId, 'low.resource-stability', title);
    assert.equal(result.severityOriginal, 'high', title);
  }

  // 正文/类别含 ProcessBuilder、命令执行只是机制描述，实际影响是进程表耗尽
  const shellLeak = applySeverityPolicy({
    title: 'LinuxShellExecutor.execute —— 超时后后台进程泄漏导致进程表/资源耗尽',
    category: '资源耗尽-命令执行',
    description:
      '超时后将命令添加 & 后缀用 ProcessBuilder("/bin/bash","-c",command) 重新后台执行，耗尽系统进程表导致 DoS，并非命令注入或未授权 RCE',
    severity: 'critical',
  });
  assert.equal(shellLeak.severity, 'low');
  assert.equal(shellLeak.ruleId, 'low.resource-stability');
  assert.equal(shellLeak.protected, false);
});

test('低价值配置和纯信息暴露降为 info', () => {
  const cases = [
    '缺少 X-Frame-Options 安全响应头',
    'Server Banner 版本号暴露',
    'Swagger API 文档公开但接口正常鉴权',
    'Source Map 暴露但不包含密钥',
  ];
  for (const title of cases) {
    const result = applySeverityPolicy({ title, severity: 'high' });
    assert.equal(result.severity, 'info', title);
    assert.equal(result.ruleId, 'info.configuration', title);
  }

  const phpDevServer = applySeverityPolicy({
    title: '生产环境使用 PHP 内置开发服务器',
    category: '不安全默认配置、容器安全缺陷',
    description: 'Dockerfile 使用 php -S 0.0.0.0:8000，单线程易 DoS，缺少安全头',
    severity: 'high',
    severity_original: 'critical',
    regrade_reason:
      "原 critical 偏高。主要危害是易受 DoS，未达到'完全接管/大规模脱库/未授权 RCE'的 critical 标准。",
  });
  assert.equal(phpDevServer.severity, 'info');
  assert.equal(phpDevServer.ruleId, 'info.configuration');
  assert.equal(phpDevServer.protected, false);

  const artisanServe = applySeverityPolicy({
    title: 'Docker 生产环境使用 Laravel 内置开发服务器（php artisan serve）',
    category: '安全配置错误',
    description: '单线程无 HTTPS；若另有文件上传漏洞可能被放大，但本条本身是配置问题',
    severity: 'high',
    regrade_reason: '使文件上传直接升级为RCE，单线程极易被DoS打垮',
  });
  assert.equal(artisanServe.severity, 'info');
  assert.equal(artisanServe.ruleId, 'info.configuration');
});

test('弱防护和反射型 XSS 封顶为 low', () => {
  const cases = [
    '登录接口缺少速率限制',
    '密码策略偏弱且复杂度不足',
    'CORS 配置允许任意来源，但接口无敏感数据',
    '搜索参数存在反射型 XSS',
    'logout.php—登出请求的CSRF防护 (formhash验证) 被注释禁用',
    'CSRF防护完全缺失',
  ];
  for (const title of cases) {
    const result = applySeverityPolicy({ title, severity: 'critical' });
    assert.equal(result.severity, 'low', title);
  }

  const reflectedWithDomSink = applySeverityPolicy({
    title: '请求 URI 反射型 XSS',
    description: '未经转义后通过 innerHTML 注入页面',
    severity: 'critical',
  });
  assert.equal(reflectedWithDomSink.severity, 'low');
  assert.equal(reflectedWithDomSink.ruleId, 'low.frontend');
});

test('Sink 级 SSRF 原语封顶为 low；带入口的打点链不误伤', () => {
  const sinkCases = [
    '_dfsockopen—核心网络函数无协议限制+跟随重定向+回退至fopen',
    'curl_file_get_contents/dzz_file_get_contents——核心函数无协议限制+跟随重定向+SSL禁用',
    'curl\\_file\\_get\\_contents/dzz\\_file\\_get\\_contents—核心函数无协议限制+跟随重定向+SSL禁用',
    'curl_exec_redir——自定义重定向追踪未校验重定向目标IP',
    'curl\\_exec\\_redir—自定义重定向追踪未校验重定向目标IP',
    'CURLOPT_FOLLOWLOCATION 开启 SSRF 内网穿透',
  ];
  for (const title of sinkCases) {
    const result = applySeverityPolicy({ title, severity: 'critical', category: 'SSRF' });
    assert.equal(result.severity, 'low', title);
    assert.equal(result.ruleId, 'low.sink-ssrf-primitive', title);
  }

  const withEntry = applySeverityPolicy({
    title: "admin/appmarket/edit.php后台应用图标编辑处直接SSRF（$_GET['iconnew']未经校验传入curl_exec）",
    category: 'SSRF',
    severity: 'high',
  });
  assert.equal(withEntry.severity, 'high');
  assert.equal(withEntry.ruleId, null);
  assert.equal(withEntry.changed, false);

  const callSite = applySeverityPolicy({
    title: 'class\\_image.php:133—dfsockopen传入外部图片路径可能导致SSRF',
    category: 'SSRF',
    severity: 'high',
  });
  assert.equal(callSite.severity, 'high');
  assert.equal(callSite.changed, false);
});

test('理论不可达问题降为 info', () => {
  const result = applySeverityPolicy({
    title: '潜在整数溢出',
    description: '输入不可控，无法由外部触发',
    severity: 'medium',
  });
  assert.equal(result.severity, 'info');
  assert.equal(result.ruleId, 'info.theoretical');
});

test('规则只降不升且可重复应用', () => {
  const first = applySeverityPolicy({
    title: '内存泄漏导致资源耗尽',
    severity: 'critical',
    regrade_reason: '模型原始理由',
  });
  assert.equal(first.severity, 'low');
  assert.match(first.regradeReason ?? '', /\[自动降级:low\.resource-stability\]/);

  const second = applySeverityPolicy({
    title: '内存泄漏导致资源耗尽',
    severity: first.severity,
    severity_original: first.severityOriginal,
    regrade_reason: first.regradeReason,
  });
  assert.equal(second.severity, 'low');
  assert.equal(second.changed, false);
  assert.equal(
    (second.regradeReason ?? '').match(/\[自动降级:low\.resource-stability\]/g)?.length,
    1
  );

  const alreadyInfo = applySeverityPolicy({
    title: '请求体无上限导致 OOM',
    severity: 'info',
  });
  assert.equal(alreadyInfo.severity, 'info');
});

/* ---------------------------------------------------------------------------
 * 去除高危保护后：红队二次验证的实战评级为准，本函数不再把高危类别拉回原等级。
 * 只要不是明确的低价值类别，评级完全维持红队结论（既不升级也不降级）。
 * ------------------------------------------------------------------------- */

test('已移除高危保护：低价值以外的类别完全维持红队评级', () => {
  const sqli = applySeverityPolicy({
    title: 'author__not_in 未经 absint 拼入 NOT IN 导致 SQL 注入',
    severity: 'low',
    severity_original: 'critical',
    policy_baseline_severity: 'critical',
  });
  assert.equal(sqli.severity, 'low');
  assert.equal(sqli.changed, false);
  assert.equal(sqli.ruleId, null);
  assert.equal(sqli.protected, false);

  const rce = applySeverityPolicy({
    title: '未授权命令注入导致远程代码执行',
    severity: 'critical',
  });
  assert.equal(rce.severity, 'critical');
  assert.equal(rce.changed, false);
  assert.equal(rce.protected, false);

  const authBypass = applySeverityPolicy({
    title: '任意用户密码可被修改导致账号接管',
    severity: 'medium',
    severity_original: 'critical',
    policy_baseline_severity: 'critical',
  });
  assert.equal(authBypass.severity, 'medium');
  assert.equal(authBypass.changed, false);
  assert.equal(authBypass.protected, false);
});

test('高危类别若命中低价值描述仍会被封顶（降级依旧生效）', () => {
  // 标题是资源耗尽（低价值），即便文中出现命令执行机制描述也照常降级。
  const dosOnly = applySeverityPolicy({
    title: '请求体无限制造成资源耗尽 DoS',
    severity: 'high',
    regrade_reason:
      '实际可利用性较低。\n[自动降级:low.resource-stability] 纯资源或稳定性问题，不涉及 RCE 或代码执行',
  });
  assert.equal(dosOnly.severity, 'low');
  assert.equal(dosOnly.ruleId, 'low.resource-stability');
});

test('历史 severity_original 仅用于展示，绝不据此反向升级', () => {
  const result = applySeverityPolicy({
    title: '历史记录中的命令注入',
    severity: 'low',
    severity_original: 'critical',
  });
  assert.equal(result.severity, 'low');
  assert.equal(result.changed, false);
  assert.equal(result.protected, false);
});

/* ---------------------------------------------------------------------------
 * 新增低价值族封顶规则（令牌生命周期 / 传输未加密 / CORS 过宽 / 缺安全响应头），
 * 并确保"硬编码密钥可伪造令牌""CORS 携带凭据窃取敏感数据"等真高危不被误降。
 * ------------------------------------------------------------------------- */

test('令牌/会话生命周期缺陷封顶为 low', () => {
  const cases = [
    'API令牌双重安全机制失效——永久有效+明文存储',
    'Bearer Token 无主动失效/撤销机制——Token 签发后永久有效',
    'JWT令牌永不过期——createAccessToken/createServiceToken缺失withExpiresAt()',
    'Sanctum API令牌永不过期——需DB泄露配合利用',
    'logout 登出后 Session 未吊销仍可继续使用',
  ];
  for (const title of cases) {
    const result = applySeverityPolicy({ title, severity: 'critical' });
    assert.equal(result.severity, 'low', title);
    assert.equal(result.ruleId, 'low.credential-lifecycle', title);
  }
});

test('硬编码密钥可伪造令牌属真高危，生命周期规则不得误降', () => {
  const forge = applySeverityPolicy({
    title: 'JWT私钥硬编码可伪造任意身份令牌且令牌永不过期',
    severity: 'critical',
  });
  assert.equal(forge.severity, 'critical');
  assert.equal(forge.changed, false);

  const sameKey = applySeverityPolicy({
    title: 'Refresh Token密钥硬编码可伪造长期有效令牌',
    severity: 'critical',
  });
  assert.equal(sameKey.severity, 'critical');
  assert.equal(sameKey.changed, false);
});

test('未强制 HTTPS / 传输未加密封顶为 low', () => {
  const cases = [
    'HTTPS强制默认关闭',
    '缺少HTTPS强制跳转导致凭证明文传输',
    'config.TEMPLATE.inc.php —— force_login_ssl默认关闭登录凭证明文传输',
    'REDIRECT_TO_HTTPS=0 默认禁用 HTTPS 重定向',
  ];
  for (const title of cases) {
    const result = applySeverityPolicy({ title, severity: 'high' });
    assert.equal(result.severity, 'low', title);
    assert.equal(result.ruleId, 'low.transport-tls', title);
  }
});

test('CORS 过宽无凭据封顶为 low；携带凭据窃取敏感数据不降级', () => {
  const open = applySeverityPolicy({
    title: 'API 插件 Access-Control-Allow-Origin: * 任意网站可跨域读取 API',
    category: 'CORS跨域配置',
    severity: 'critical',
  });
  assert.equal(open.severity, 'low');
  assert.equal(open.ruleId, 'low.cors-open');

  const withCreds = applySeverityPolicy({
    title: 'CORS配置回显Origin头跨域凭据泄露',
    category: 'CORS跨域配置',
    severity: 'high',
  });
  assert.equal(withCreds.severity, 'high');
  assert.equal(withCreds.changed, false);

  const credentialSteal = applySeverityPolicy({
    title: 'CORS JSON/JSONP模板允许跨域且携带凭据导致敏感数据可被跨域窃取',
    category: 'CORS跨域配置',
    severity: 'high',
  });
  assert.equal(credentialSteal.severity, 'high');
  assert.equal(credentialSteal.changed, false);
});

test('仅缺安全响应头/CSP（含点击劫持）降为 info', () => {
  const cases = [
    '前端缺失X-Frame-Options/XSS点击劫持',
    '缺失 Content-Security-Policy 头——任意脚本执行',
    '缺少 HSTS / Strict-Transport-Security 响应头',
  ];
  for (const title of cases) {
    const result = applySeverityPolicy({ title, severity: 'high' });
    assert.equal(result.severity, 'info', title);
    assert.equal(result.ruleId, 'info.security-headers', title);
  }
});
