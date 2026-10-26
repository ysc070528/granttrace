"""Array evidence paths remain readable without bypassing secret redaction."""

import unittest

from core.evidence import sanitize_evidence


class EvidencePathTests(unittest.TestCase):
    def test_exact_array_paths_survive_repeated_output_boundaries(self):
        evidence = {"decision_evidence": {
            key: ["[0].item", "records[2].note"]
            for key in ("private_data_paths", "owner_private_data_paths", "matched_private_data_paths")}}
        self.assertEqual(evidence, sanitize_evidence(sanitize_evidence(evidence)))

    def test_path_metadata_still_redacts_known_credentials(self):
        result = sanitize_evidence({"private_data_paths": ["[0].credentialvalue"]},
                                   secret_values=["credentialvalue"])
        self.assertNotIn("credentialvalue", str(result))

    def test_json_disguised_as_path_metadata_is_structurally_redacted(self):
        evidence = {"private_data_paths": ['[{"password":"secret-value"}]', '[0].item secret-value']}
        result = sanitize_evidence(evidence)
        self.assertNotIn("secret-value", result["private_data_paths"][0])
        self.assertIn("UNPARSEABLE", result["private_data_paths"][1])

    def test_business_body_does_not_gain_path_metadata_exemption(self):
        result = sanitize_evidence({"body": '{"private_data_paths":["[0].item"]}'})
        self.assertIn("UNPARSEABLE", result["body"])


if __name__ == "__main__":
    unittest.main()
