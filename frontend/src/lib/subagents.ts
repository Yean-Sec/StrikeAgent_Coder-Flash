/** 与 backend/src/schema.ts SUBAGENTS_BY_LANG 路数对齐：每语言最多 4 路，CWE 面合并进同一智能体。 */
export const SUBAGENT_LANES: Record<string, number> = {
  java: 4,
  go: 4,
  python: 4,
  php: 4,
  jsts: 4,
  rust: 4,
  ruby: 4,
  csharp: 4,
  c: 4,
  cpp: 4,
  solidity: 4,
};

export const SUBAGENT_TRAIT_HINT: Record<string, string> = {
  java: '4 路覆盖 CWE-89/78/22/918/862/502/917：SQL+SSRF、RCE+表达式/JNDI、文件+Zip Slip、鉴权+反序列化+配置',
  go: '4 路覆盖 CWE-89/78/22/918/862/502：SQL+SSRF、命令+模板、路径+gob/yaml、鉴权+并发 DoS',
  python: '4 路覆盖 CWE-89/78/22/918/502/1336：SQL+SSRF、命令+SSTI、路径+Zip/Tar+pickle、鉴权+配置',
  php: '4 路覆盖 CWE-89/78/98/918/502：SQL+SSRF、命令+模板/配置注入、包含+路径上传、鉴权+反序列化',
  jsts: '4 路覆盖 CWE-89/78/22/918/502/1321/1336：SQL+SSRF、命令+SSTI、路径、鉴权+反序列化+原型污染',
  rust: '4 路覆盖 CWE-89/78/22/918/119/400：命令、SQL+SSRF+路径、unsafe 内存+panic DoS、鉴权+反序列化',
  ruby: '4 路覆盖 CWE-89/78/22/918/502/915：SQL+SSRF、命令+SSTI、路径+Marshal+批量赋值、鉴权+配置',
  csharp: '4 路覆盖 CWE-89/78/22/918/502/611：SQL+SSRF+XXE、命令+Razor、路径+反序列化、鉴权+配置',
  c: '4 路覆盖 CWE-119/416/362/190/78/134：内存破坏、命令+文件+内核权限、格式化/SQL/密码学、竞态+整数/资源',
  cpp: '4 路覆盖 CWE-119/843/362/190/78：内存/类型混淆、命令+文件、注入+密码学、竞态+RAII/资源',
  solidity: '4 路覆盖 CWE-841/284/190：重入+状态机、访问控制、算术、预言机+Gas',
};

export function subagentCountForLanguage(lang: string): number {
  return SUBAGENT_LANES[lang] || 0;
}
