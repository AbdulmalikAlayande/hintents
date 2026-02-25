#!/usr/bin/env ts-node
// Companion bot script that posts human-readable failure reasons on PRs when tagged.

import axios from "axios";
import fs from "fs";
import { formatFailureComment, pickFailingJob, pickLatestFailedRun } from "../src/utils/prFailureSummary";

function requireEnv(name: string): string {
  const val = process.env[name];
  if (!val) {
    throw new Error(`${name} is required`);
  }
  return val;
}

async function main() {
  const token = requireEnv("GITHUB_TOKEN");
  const repoEnv = requireEnv("GITHUB_REPOSITORY");
  const eventPath = requireEnv("GITHUB_EVENT_PATH");

  const [owner, repo] = repoEnv.split("/");
  const event = JSON.parse(fs.readFileSync(eventPath, "utf8"));

  const body: string = event?.comment?.body ?? "";
  const isTag = /@erst-bot\b|\/erst-bot\b|\/erst-reason\b/i.test(body);
  if (!isTag) {
    console.log("No bot tag present; skipping.");
    return;
  }

  if (!event?.issue?.pull_request) {
    console.log("Comment not on a pull request; skipping.");
    return;
  }

  const prNumber: number = event.issue.number;
  const api = axios.create({
    baseURL: "https://api.github.com",
    headers: {
      Authorization: `Bearer ${token}`,
      "User-Agent": "hintents-pr-failure-bot",
      Accept: "application/vnd.github+json",
    },
  });

  const prResp = await api.get(`/repos/${owner}/${repo}/pulls/${prNumber}`);
  const headSha: string | undefined = prResp.data?.head?.sha;
  const branch: string | undefined = prResp.data?.head?.ref;

  const runsResp = await api.get(`/repos/${owner}/${repo}/actions/runs`, {
    params: {
      event: "pull_request",
      per_page: 20,
      status: "completed",
      branch,
    },
  });

  const runs = runsResp.data?.workflow_runs ?? [];
  const failedRun = pickLatestFailedRun(runs, headSha);

  if (!failedRun) {
    await api.post(`/repos/${owner}/${repo}/issues/${prNumber}/comments`, {
      body: `Failure reason bot report\n- No failing workflow runs were found for commit ${headSha ?? "unknown"}.`,
    });
    return;
  }

  const jobsResp = await api.get(`/repos/${owner}/${repo}/actions/runs/${failedRun.id}/jobs`, {
    params: { per_page: 50 },
  });

  const { job, step } = pickFailingJob(jobsResp.data?.jobs ?? []);
  const comment = formatFailureComment({ run: failedRun, job, step });

  await api.post(`/repos/${owner}/${repo}/issues/${prNumber}/comments`, { body: comment });
}

main().catch((err) => {
  console.error(`[pr-failure-reason] ${err.message}`);
  process.exit(1);
});
