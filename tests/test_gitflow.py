import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("gitflow", Path(__file__).resolve().parents[1] / "scripts/check_gitflow.py")
gitflow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gitflow)


class GitflowTest(unittest.TestCase):
    def setUp(self):
        self.pr = {
            "head": {"ref": "feature/1-ansible-portal"}, "base": {"ref": "develop"},
            "body": "Implementar portal. Closes #1", "labels": [{"name": "type::feature"}], "milestone": {"id": 2},
        }
        self.issue = {"state": "open", "labels": [{"name": "type::feature"}], "milestone": {"id": 2}}

    def test_valid_pr(self):
        gitflow.check_pr(self.pr, self.issue, ["feat: configurar portal con Ansible"])

    def test_rejects_invalid_metadata_and_commits(self):
        for mutation in [
            {"base": {"ref": "main"}}, {"head": {"ref": "feature/ansible"}},
            {"body": "Closes #12"}, {"milestone": None}, {"labels": []},
            {"labels": [{"name": "type::feature"}, {"name": "type::chore"}]},
        ]:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                gitflow.check_pr({**copy.deepcopy(self.pr), **mutation}, self.issue, ["feat: configurar portal con Ansible"])
        for subjects in [[], ["wip"], ["x" * 73]]:
            with self.subTest(subjects=subjects), self.assertRaises(ValueError):
                gitflow.check_pr(self.pr, self.issue, subjects)
