import copy
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch


class DetectorAuthorizationTest(unittest.TestCase):
    def setUp(self):
        env = {name: "test-value" for name in [
            "INCIDENTS_TABLE", "STATE_TABLE", "EVIDENCE_BUCKET", "SNS_TOPIC_ARN", "CONFIG_KEY"
        ]}
        path = Path(__file__).resolve().parents[1] / "terraform-tesis-ir-secure-portal/lambda/lambda_function.py"
        with patch.dict(os.environ, env), patch("boto3.resource"), patch("boto3.client"):
            spec = importlib.util.spec_from_file_location("detector_authorization", path)
            self.detector = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.detector)
        counter = patch.object(self.detector, "increment_counter", return_value=1)
        once = patch.object(self.detector, "mark_alert_once", return_value=True)
        counter.start()
        once.start()
        self.addCleanup(counter.stop)
        self.addCleanup(once.stop)
        self.role = "arn:aws:iam::123456789012:role/response-worker"
        self.config = {
            "authorized_admin_users": ["admin-tesis"],
            "authorized_ips": ["192.0.2.10/32"],
            "automated_response_role_arns": [self.role],
        }
        self.event = {
            "eventName": "AttachRolePolicy", "eventSource": "iam.amazonaws.com",
            "sourceIPAddress": "192.0.2.10",
            "userIdentity": {"type": "IAMUser", "userName": "admin-tesis"},
        }

    def test_admin_exemption_requires_both_identity_and_allowed_ip(self):
        self.assertIsNone(self.detector.analyze_cloudtrail(self.event, self.config))
        for name, ip in [("other-user", "192.0.2.10"), ("admin-tesis", "198.51.100.20")]:
            event = copy.deepcopy(self.event)
            event["userIdentity"]["userName"] = name
            event["sourceIPAddress"] = ip
            payload, _ = self.detector.analyze_cloudtrail(event, self.config)
            self.assertEqual(payload["incident_type"], "PRIVILEGE_ESCALATION")

    def test_response_role_exemption_is_limited_to_expected_iam_actions(self):
        event = copy.deepcopy(self.event)
        event["sourceIPAddress"] = "198.51.100.20"
        event["userIdentity"] = {
            "type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/response-worker/session",
            "sessionContext": {"sessionIssuer": {"arn": self.role}},
        }
        for action in ["ListAccessKeys", "UpdateAccessKey", "PutUserPolicy"]:
            event["eventName"] = action
            self.assertIsNone(self.detector.analyze_cloudtrail(event, self.config))
        event["eventName"] = "CreateAccessKey"
        payload, _ = self.detector.analyze_cloudtrail(event, self.config)
        self.assertEqual(payload["incident_type"], "PRIVILEGE_ESCALATION")
        event["eventName"] = "PutUserPolicy"
        event["userIdentity"]["sessionContext"]["sessionIssuer"]["arn"] = self.role + "-other"
        payload, _ = self.detector.analyze_cloudtrail(event, self.config)
        self.assertEqual(payload["incident_type"], "PRIVILEGE_ESCALATION")

    def test_authorized_admin_from_foreign_ip_still_triggers_credential_leak(self):
        event = copy.deepcopy(self.event)
        event.update(eventName="GetCallerIdentity", eventSource="sts.amazonaws.com", sourceIPAddress="198.51.100.20")
        payload, _ = self.detector.analyze_cloudtrail(event, self.config)
        self.assertEqual(payload["incident_type"], "CREDENTIAL_LEAK")
