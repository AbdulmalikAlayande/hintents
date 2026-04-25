import { formatFailureComment, pickFailingJob, pickLatestFailedRun, WorkflowJob, WorkflowRun } from "../src/utils/prFailureSummary";

describe("prFailureSummary helpers", () => {
  const runs: WorkflowRun[] = [
    { id: 1, name: "CI", run_number: 10, conclusion: "success", head_sha: "aaa", html_url: "https://example.com/run/1" },
    { id: 2, name: "CI", run_number: 11, conclusion: "failure", head_sha: "bbb", html_url: "https://example.com/run/2" },
    { id: 3, name: "CI", run_number: 12, conclusion: "failure", head_sha: "ccc", html_url: "https://example.com/run/3" }
  ];

  it("picks latest failed run matching head sha", () => {
    const picked = pickLatestFailedRun(runs, "ccc");
    expect(picked?.id).toBe(3);
  });

  it("returns undefined when no failures", () => {
    const picked = pickLatestFailedRun(runs.slice(0, 1), "aaa");
    expect(picked).toBeUndefined();
  });

  it("locates failing job and step", () => {
    const jobs: WorkflowJob[] = [
      { id: 1, name: "lint", conclusion: "success" },
      { id: 2, name: "test", conclusion: "failure", html_url: "https://example.com/job/2", steps: [
        { name: "Install deps", conclusion: "success" },
        { name: "Run tests", conclusion: "failure" }
      ]}
    ];

    const { job, step } = pickFailingJob(jobs);
    expect(job?.name).toBe("test");
    expect(step?.name).toBe("Run tests");
  });

  it("formats a readable comment", () => {
    const comment = formatFailureComment({
      run: runs[2],
      job: { id: 2, name: "test", conclusion: "failure", html_url: "https://example.com/job/2" },
      step: { name: "Run tests", conclusion: "failure" }
    });

    expect(comment).toContain("Workflow: CI (run #12)");
    expect(comment).toContain("Job: test (failure)");
    expect(comment).toContain("Failing step: Run tests");
    expect(comment).toContain("Job logs: https://example.com/job/2");
  });
});
