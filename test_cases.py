
import unittest
from pathlib import Path

from log_parser import parse_logs
from analyzer import analyze_logs




BASE_DIR = Path(__file__).resolve().parent
SAMPLES = BASE_DIR / "sample_logs"


def investigate(relative_path):
    """Read a sample log and run it through the parser and analyzer."""
    path = SAMPLES / relative_path

    log_text = path.read_text(encoding="utf-8")
    df, invalid = parse_logs(log_text)
    result = analyze_logs(df)

    return df, invalid, result


class TestRootCauseAI(unittest.TestCase):

    

    def test_database_failure(self):
        df, invalid, result = investigate(
            "database_failure.log"
        )

        self.assertEqual(len(df), 15)
        self.assertEqual(len(invalid), 0)
        self.assertEqual(
            result["hypothesis"]["id"],
            "database_pool_exhaustion"
        )


    def test_empty_file(self):
        df, invalid, result = investigate(
            "edge_cases/empty.log"
        )

        self.assertTrue(df.empty)
        self.assertEqual(result["status"], "no_data")
        self.assertIsNone(result["hypothesis"])


    def test_malformed_logs(self):
        df, invalid, result = investigate(
            "edge_cases/malformed.log"
        )

        self.assertTrue(df.empty)
        self.assertEqual(len(invalid), 5)
        self.assertIsNone(result["hypothesis"])

    # Check that valid entries are still analyzed when some lines are malformed.

    def test_mixed_quality_logs(self):
        df, invalid, result = investigate(
            "edge_cases/mixed_quality.log"
        )

        self.assertEqual(len(df), 5)
        self.assertEqual(len(invalid), 2)
        self.assertEqual(
            result["hypothesis"]["id"],
            "database_pool_exhaustion"
        )


    def test_out_of_order_logs(self):
        df, invalid, result = investigate(
            "edge_cases/out_of_order.log"
        )

        self.assertTrue(
            df["timestamp"].is_monotonic_increasing
        )
        self.assertEqual(
            result["hypothesis"]["id"],
            "database_pool_exhaustion"
        )

    

    def test_unknown_failure(self):
        df, invalid, result = investigate(
            "edge_cases/unknown_failure.log"
        )

        self.assertEqual(result["status"], "no_known_pattern")
        self.assertIsNone(result["hypothesis"])
        self.assertEqual(result["summary"]["error_count"], 3)


    def test_multiple_independent_incidents(self):
        df, invalid, result = investigate(
            "edge_cases/multiple_incidents.log"
        )

        self.assertEqual(
            result["hypothesis"]["id"],
            "database_pool_exhaustion"
        )

        evidence_services = {
            event["service"]
            for event in result["evidence"]
        }

        self.assertNotIn(
            "ImageService",
            evidence_services
        )

        
        self.assertIn("Database", evidence_services)
        self.assertIn("OrderService", evidence_services)

        timeline_services = {
            event["service"]
            for event in result["timeline"]
        }

        self.assertIn("ImageService", timeline_services)



    def test_healthy_application(self):
        df, invalid, result = investigate(
            "healthy_application.log"
        )

        self.assertEqual(len(df), 6)
        self.assertEqual(result["summary"]["error_count"], 0)
        self.assertIsNone(result["hypothesis"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
