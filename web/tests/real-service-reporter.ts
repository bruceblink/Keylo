import type { FullResult, Reporter, TestCase, TestResult } from '@playwright/test/reporter';

// Emit only known scenario names and status. Standard reporters include call
// logs and attachments that can reveal authentication data on failures.
export default class RealServiceReporter implements Reporter {
  private passed = 0;
  private failed = 0;

  onTestEnd(test: TestCase, result: TestResult) {
    if (result.status === 'passed') this.passed += 1;
    else this.failed += 1;
    const stagePattern = /Real-service check failed: (?:OIDC recovery navigation|SMTP account recovery lifecycle) at ([a-z0-9_]+)\. Sensitive diagnostics suppressed\./;
    const safeStage = result.errors
      .map((error) => error.message?.match(stagePattern)?.[1])
      .find((stage) => stage !== undefined);
    const failureStage = result.status === 'passed' ? '' : ` at ${safeStage ?? 'unclassified'}`;
    console.log(`[real-browser] ${test.title}: ${result.status}${failureStage}`);
  }

  onEnd(result: FullResult) {
    console.log(`[real-browser] ${result.status}; ${this.passed} passed, ${this.failed} failed`);
  }
}
