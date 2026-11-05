import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "inventory", Path(__file__).resolve().parents[1] / "ansible/scripts/generate_inventory.py"
)
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self.values = dict(instance_id="i-0123456789abcdef0", public_ip="192.0.2.10", region="us-east-2",
                           asset_name="custom-portal", log_group="/aws/ec2/custom", ssm_bucket="custom-transfer", ssh_key="")

    def test_ssm_preserves_terraform_parameters_without_ssh_key(self):
        group = inventory.build_inventory(self.values)["all"]["children"]["portal"]
        host = group["hosts"]["portal_ec2"]
        self.assertEqual(host["ansible_host"], self.values["instance_id"])
        self.assertEqual(host["ansible_aws_ssm_bucket_name"], self.values["ssm_bucket"])
        self.assertEqual(group["vars"]["cloudwatch_agent_log_group"], self.values["log_group"])

    def test_ssh_requires_key_pair_and_uses_public_address(self):
        with self.assertRaisesRegex(ValueError, "ssh_key"):
            inventory.build_inventory(self.values, "ssh")
        self.values["ssh_key"] = "tesis"
        host = inventory.build_inventory(self.values, "ssh")["all"]["children"]["portal"]["hosts"]["portal_ec2"]
        self.assertEqual(host["ansible_host"], self.values["public_ip"])
        self.assertEqual(host["ansible_connection"], "ssh")

    def test_incomplete_output_fails_before_generating_inventory(self):
        for key in ["instance_id", "region", "asset_name", "log_group", "ssm_bucket"]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                inventory.build_inventory({**self.values, key: ""})
