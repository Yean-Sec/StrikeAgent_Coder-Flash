import path from 'path';

/**
 * 历史最小运行时落盘目录。远程验证已下线该路径，不再写入；
 * 仅供覆盖审计扫描旧产物、以及重跑时清理残留。
 */
export function miniVerifyDir(codeDir: string): string {
  return path.join(codeDir, '_mini_verify');
}
