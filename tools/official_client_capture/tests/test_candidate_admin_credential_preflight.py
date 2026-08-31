"""候选辅助场景管理凭据前置检查测试。"""

from __future__ import annotations

import base64
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from tools.official_client_capture.capturelib.model import ConfigurationError
from tools.official_client_capture.codex_upgrade import (
    Job,
    _validate_candidate_admin_credential,
)


def _token(expires_at: int) -> str:
    def encoded(value: object) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{encoded({'alg': 'HS256'})}.{encoded({'exp': expires_at})}.signature"


class CandidateAdminCredentialPreflightTests(unittest.TestCase):
    @staticmethod
    def _job(job_id: str = "candidate-frozen-aux") -> Job:
        return Job(
            job_id=job_id,
            phase="candidate",
            suites=("full",),
            description="测试任务",
            steps=(),
            evidence_roots=(),
            covers=(),
        )

    def test_unrelated_job_does_not_require_admin_credential(self) -> None:
        with mock.patch.dict(
            "os.environ",
            {},
            clear=True,
        ):
            _validate_candidate_admin_credential([self._job("candidate-core")])

    def test_missing_credential_fails_before_candidate_jobs(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(ConfigurationError, "缺少合法管理凭据"):
                _validate_candidate_admin_credential([self._job()])

    def test_private_token_file_with_sufficient_ttl_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "admin-token"
            path.write_text(_token(int(time.time()) + 3600), encoding="utf-8")
            path.chmod(0o400)
            with mock.patch.dict(
                "os.environ",
                {"ADMIN_BEARER_TOKEN_FILE": str(path)},
                clear=True,
            ):
                _validate_candidate_admin_credential([self._job()])

    def test_expiring_token_fails_before_reservation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "admin-token"
            path.write_text(_token(int(time.time()) + 60), encoding="utf-8")
            path.chmod(0o400)
            with mock.patch.dict(
                "os.environ",
                {"ADMIN_BEARER_TOKEN_FILE": str(path)},
                clear=True,
            ):
                with self.assertRaisesRegex(ConfigurationError, "剩余有效期不足"):
                    _validate_candidate_admin_credential([self._job()])


if __name__ == "__main__":
    unittest.main()
