import { backfillExistingLogsToSqlite } from '../src/logRetention';
import { setSetting } from '../src/settings';

const result = backfillExistingLogsToSqlite();
if (result.projects_missing_second_layer !== 0) {
  console.error(JSON.stringify(result, null, 2));
  process.exitCode = 1;
} else {
  setSetting('sqlite_dual_log_backfill_v1', '1');
  console.log(JSON.stringify(result, null, 2));
}
