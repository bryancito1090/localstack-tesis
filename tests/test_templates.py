import json
from pathlib import Path
import unittest

from jinja2 import Environment, FileSystemLoader, StrictUndefined
import yaml

ROOT = Path(__file__).resolve().parents[1] / "ansible"


class TemplatesTest(unittest.TestCase):
    def test_all_templates_render_and_cloudwatch_uses_inventory_values(self):
        values = yaml.safe_load((ROOT / "inventory/group_vars/all.yml").read_text())
        values.update(cloudwatch_agent_region="eu-west-1", cloudwatch_agent_log_group="/custom/portal")
        rendered = {}
        for directory in (ROOT / "roles").glob("*/templates"):
            env = Environment(loader=FileSystemLoader(directory), undefined=StrictUndefined)
            env.filters["to_json"] = json.dumps
            for name in env.list_templates():
                rendered[name] = env.get_template(name).render(values)
        config = json.loads(rendered["config.json.j2"])
        self.assertEqual(config["agent"]["region"], "eu-west-1")
        logs = config["logs"]["logs_collected"]["files"]["collect_list"]
        self.assertEqual(len({entry["log_stream_name"] for entry in logs}), len(logs))
        self.assertTrue(all(entry["log_group_name"] == "/custom/portal" for entry in logs))
        self.assertIn("/var/log/tesis-portal/app.log", [entry["file_path"] for entry in logs])
