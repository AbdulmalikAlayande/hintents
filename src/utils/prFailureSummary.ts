// Copyright 2026 Erst Users
// SPDX-License-Identifier: Apache-2.0

export type WorkflowRun = {
  id: number;
  name: string;
  run_number: number;
  conclusion: string | null;
  head_sha?: string;
  html_url?: string;
};

export type WorkflowJob = {
  id: number;
  name: string;
  conclusion: string | null;
  html_url?: string;
  steps?: WorkflowStep[];
};

export type WorkflowStep = {
  name: string;
  conclusion: string | null;
};

const failureStates = new Set(['failure', 'timed_out', 'cancelled', 'action_required']);

export function isFailure(conclusion: string | null | undefined): boolean {
  if (!conclusion) return false;
  return failureStates.has(conclusion.toLowerCase());
}

export function pickLatestFailedRun(runs: WorkflowRun[], headSha?: string): WorkflowRun | undefined {
  return runs.find((run) => isFailure(run.conclusion) && (!headSha || run.head_sha === headSha));
}

export function pickFailingJob(jobs: WorkflowJob[]): { job?: WorkflowJob; step?: WorkflowStep } {
  for (const job of jobs) {
    if (!isFailure(job.conclusion)) continue;
    const step = (job.steps ?? []).find((s) => isFailure(s.conclusion));
    return { job, step };
  }
  return {};
}

export function formatFailureComment(opts: { run: WorkflowRun; job?: WorkflowJob; step?: WorkflowStep }): string {
  const { run, job, step } = opts;
  const lines: string[] = [
    'Failure reason bot report',
    `- Workflow: ${run.name} (run #${run.run_number})`,
    `- Status: ${run.conclusion ?? 'unknown'}`,
  ];

  if (job) {
    lines.push(`- Job: ${job.name} (${job.conclusion ?? 'unknown'})`);
  }

  if (step) {
    lines.push(`- Failing step: ${step.name}`);
  }

  if (job?.html_url) {
    lines.push(`- Job logs: ${job.html_url}`);
  } else if (run.html_url) {
    lines.push(`- Run logs: ${run.html_url}`);
  }

  return lines.join('\n');
}
