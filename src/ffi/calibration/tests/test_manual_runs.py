import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ci"))
import manual_runs  # noqa: E402

LABEL = "reproducible-benchmarks"


def fetcher(runs: dict[str, list[dict]], jobs: dict[int, list[dict]]):
    def fetch(repo, path, token):
        if path.startswith("actions/workflows/"):
            wf = path.split("/")[2]
            status = path.split("status=")[1].split("&")[0]
            return {"workflow_runs": [r for r in runs.get(wf, []) if r["status"] == status]}
        return {"jobs": jobs[int(path.split("/")[2])]}
    return fetch


class ManualRuns(unittest.TestCase):
    def check(self, runs, jobs):
        return manual_runs.blocking_runs("o/r", LABEL, "t", fetcher(runs, jobs))

    def test_manual_run_queued_for_this_box_blocks(self):
        runs = {"run-expb-reproducible-benchmarks.yml": [{"id": 1, "status": "queued"}]}
        jobs = {1: [{"labels": ["ubuntu-latest"], "status": "completed"}, {"labels": ["self-hosted", LABEL], "status": "queued"}]}
        self.assertEqual(len(self.check(runs, jobs)), 1)

    def test_manual_run_for_the_other_box_does_not_block(self):
        runs = {"run-rpc-benchmarks.yml": [{"id": 2, "status": "in_progress"}]}
        jobs = {2: [{"labels": ["self-hosted", "reproducible-benchmarks-arm"], "status": "in_progress"}]}
        self.assertEqual(self.check(runs, jobs), [])

    def test_manual_run_that_has_not_chosen_a_box_blocks(self):
        runs = {"run-rpc-benchmarks.yml": [{"id": 3, "status": "in_progress"}]}
        jobs = {3: [{"labels": ["ubuntu-latest"], "status": "in_progress"}]}
        self.assertEqual(len(self.check(runs, jobs)), 1)

    def test_no_manual_runs(self):
        self.assertEqual(self.check({}, {}), [])


if __name__ == "__main__":
    unittest.main()
