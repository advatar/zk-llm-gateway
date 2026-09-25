import importlib.util
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "qualify_python_v2.py"
SPEC = importlib.util.spec_from_file_location("kcf_qualifier", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class QualificationBoundaryTests(TestCase):
    def test_missing_cargo_is_blocked_not_skipped_pass(self):
        with patch.object(MODULE.shutil, "which", return_value=None):
            result = MODULE.qualify(Path("missing-sdk"), Path("missing-gateway"))
        self.assertFalse(result["qualified"])
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["native_cases_executed"], 0)
        self.assertEqual(result["observations"], [])

    def test_missing_source_cannot_qualify(self):
        with patch.object(MODULE.shutil, "which", return_value="cargo"):
            result = MODULE.qualify(Path("missing-sdk"), Path("missing-gateway"))
        self.assertFalse(result["qualified"])
        self.assertEqual(result["reason"], "source_or_lockfile_missing")
        self.assertEqual(result["native_cases_executed"], 0)
