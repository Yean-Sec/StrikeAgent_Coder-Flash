import assert from 'node:assert/strict';
import test from 'node:test';
import {
  isRceClassStrictTitle,
  isStrictHttpRemoteVerified,
  matchExploitByTitle,
} from './frontendRceCriteria';

test('中文 RCE 词不再被"未授权访问"前瞻误排除', () => {
  // 旧实现 `未授权访问(?!.*rce)` 只认英文 rce，会把这几条真前台 RCE 误判为 false
  assert.equal(isRceClassStrictTitle({ title: '未授权访问导致命令执行' }), true);
  assert.equal(isRceClassStrictTitle({ title: '未授权访问触发任意代码执行' }), true);
  assert.equal(
    isRceClassStrictTitle({ title: '未授权模块迁移触发任意PHP文件包含导致RCE' }),
    true
  );
});

test('非 RCE 类别仍判为 false', () => {
  assert.equal(isRceClassStrictTitle({ title: 'CORS 配置错误导致跨域读取', category: 'CORS' }), false);
  assert.equal(isRceClassStrictTitle({ title: '搜索参数反射型 XSS', category: 'XSS' }), false);
  assert.equal(isRceClassStrictTitle({ title: 'SSRF 服务端请求伪造' }), false);
  assert.equal(isRceClassStrictTitle({ title: '敏感信息泄露' }), false);
});

test('DoS 语境下否定式 RCE 描述仍排除', () => {
  assert.equal(
    isRceClassStrictTitle({
      title: '超时后后台进程泄漏导致进程表耗尽，并非命令注入',
      category: '资源耗尽',
    }),
    false
  );
});

test('文件上传/写入 + 执行证据判为 RCE 类', () => {
  assert.equal(isRceClassStrictTitle({ title: '通用文件上传端点任意文件上传 getshell' }), true);
  assert.equal(isRceClassStrictTitle({ title: '任意PHP文件写入 webshell' }), true);
});

test('HTTP 靶机验证：需真实交互 + 成功正向证据', () => {
  const good =
    '成功以 root 权限在容器内远程执行命令。请求 POST http://localhost:18468/api/mcp/server 返回 200，容器内 /tmp/pwned_mcp_rce.txt 验证到 uid=0(root)。';
  assert.equal(isStrictHttpRemoteVerified(good).ok, true);

  // 仅代码分析：被 reject 命中
  const staticOnly =
    '源码分析确认该端点存在命令注入，理论上可通过参数注入执行系统命令，但未搭建靶机做真实请求验证利用链。';
  assert.equal(isStrictHttpRemoteVerified(staticOnly).ok, false);

  // 只有 HTTP 400、无成功信号：不再算通过（旧实现会把 400 当证据）
  const only400 =
    '向 /api/x 发送构造请求后服务器返回 HTTP 400 Bad Request，请求被参数校验拦截，未能触发目标危险操作。';
  assert.equal(isStrictHttpRemoteVerified(only400).ok, false);

  // 空/过短
  assert.equal(isStrictHttpRemoteVerified('success').ok, false);
  assert.equal(isStrictHttpRemoteVerified('').ok, false);
});

test('最小运行时 CLI PoC 不得算作 HTTP 靶机远程成功', () => {
  const miniCli =
    '在官方 php:8.3-cli 镜像内 docker run 执行 Processor::execute()，mode=mini。' +
    '请求 GET /path 触发命令注入，uid=0(root) 验证成功。靶机 url=mini://local。';
  const r = isStrictHttpRemoteVerified(miniCli);
  assert.equal(r.ok, false);
  assert.match(r.reason, /最小运行时|CLI/);

  const modeMini =
    '成功远程执行命令。mode=mini，docker run --rm php:8.3-cli php poc.php，GET /upload 返回 200。';
  assert.equal(isStrictHttpRemoteVerified(modeMini).ok, false);
});

test('matchExploitByTitle：仅前缀相同的不同漏洞不再误配', () => {
  const exploits = [
    { vulnerability: 'POST /api/workflow 启动工作流触发 LAMBDA 代码执行', auth_required: 'none' },
    { vulnerability: 'POST /api/user/login 登录接口用户名枚举', auth_required: 'none' },
  ];
  // 精确/子串匹配命中
  const exact = matchExploitByTitle('POST /api/workflow 启动工作流触发 LAMBDA 代码执行', exploits);
  assert.equal(exact?.vulnerability, 'POST /api/workflow 启动工作流触发 LAMBDA 代码执行');

  // 另一个完全不同的漏洞标题，不应匹配到上面任何一条
  const none = matchExploitByTitle('DELETE /api/config 删除配置越权', exploits);
  assert.equal(none, null);
});
