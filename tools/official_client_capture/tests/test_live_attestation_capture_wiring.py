"""A11 的 Live attestation 注入必须受本轮四元组约束且可恢复。

Linux 生不出 DeviceCheck 值，Sub2API 为隔离抓包提供了 candidatecapture 构建；该 provider
只读进程环境，所以采集侧必须按本轮 api_key／group／account／临时代理重建服务，采集结束后
按原 compose 拉回。缺少 compose 坐标或注入失败时必须在 A11 前立即失败关闭。
"""

from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


class LiveAttestationCaptureWiringTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = Path(__file__).parents[1]
        cls.script_path = root / "run_candidate_aux_capture.sh"
        cls.script = cls.script_path.read_text(encoding="utf-8")
        cls.scenarios = json.loads(
            (root / "codex_upgrade_scenarios_0_151_0.json").read_text(encoding="utf-8")
        )
        cls.upgrade = (root / "codex_upgrade.py").read_text(encoding="utf-8")

    def test_shell_syntax_is_valid(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(self.script_path)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_注入的作用域来自本轮四元组(self) -> None:
        for env_name in (
            "SUB2API_LIVE_ATTESTATION_CAPTURE_MODE",
            "SUB2API_LIVE_ATTESTATION_CAPTURE_ACK",
            "SUB2API_LIVE_ATTESTATION_CAPTURE_API_KEY_ID",
            "SUB2API_LIVE_ATTESTATION_CAPTURE_GROUP_ID",
            "SUB2API_LIVE_ATTESTATION_CAPTURE_ACCOUNT_ID",
            "SUB2API_LIVE_ATTESTATION_CAPTURE_PROXY_NAME",
            "SUB2API_LIVE_ATTESTATION_CAPTURE_PROXY_HOST",
            "SUB2API_LIVE_ATTESTATION_CAPTURE_PROXY_PORT",
            "SUB2API_LIVE_ATTESTATION_CAPTURE_EXPIRES_AT_UNIX",
        ):
            with self.subTest(env=env_name):
                self.assertIn(env_name, self.script)
        # 四元组必须引用脚本内的真实变量，不能写死。
        self.assertIn('"$api_key_id"', self.script)
        self.assertIn('"$account_id"', self.script)
        self.assertIn('"$proxy_name"', self.script)
        self.assertIn('"$relay_port"', self.script)

    def test_有效期短于_provider_上限(self) -> None:
        # provider 拒绝超过 20 分钟的窗口；脚本取 900 秒留足余量。
        self.assertIn("+ 900 ))", self.script)

    def test_注入发生在第一跳之前且结束后恢复(self) -> None:
        inject = self.script.index("if ! deploy_with_live_attestation; then")
        first_hop = self.script.index("A11-live-first-hop")
        self.assertLess(inject, first_hop)
        self.assertIn("restore_deploy_without_live_attestation", self.script)
        self.assertIn("restore_failed=1", self.script)

    def test_重建容器后补装抓包_CA(self) -> None:
        """compose 重建是全新容器，不补 CA 会在第一跳 TLS 阶段被自己的 relay 证书挡下。"""

        inject = self.script.index("deploy_with_live_attestation() {")
        body = self.script[inject : self.script.index("\nrestore_deploy_without_live_attestation")]
        self.assertIn('docker cp "$ca_cert"', body)
        self.assertIn("update-ca-certificates", body)
        self.assertIn("restart_service", body)

    def test_恢复部署早于_hosts_回灌(self) -> None:
        """恢复部署会重建容器、Docker 重新生成 hosts；顺序反了复核必然不一致。"""

        redeploy = self.script.index("restore_deploy_without_live_attestation || restore_failed=1")
        hosts_restore = self.script.index('hosts.before" "$service_container:/tmp/candidate-aux-hosts.restore"')
        self.assertLess(redeploy, hosts_restore)

    def test_缺少坐标时在_a11_前失败关闭(self) -> None:
        self.assertIn(
            'if [[ -z ${LIVE_ATTESTATION_COMPOSE_DIR:-} || -z ${LIVE_ATTESTATION_COMPOSE_FILES:-} ]]; then',
            self.script,
        )
        self.assertIn("缺少 Live attestation compose 目录或文件", self.script)
        self.assertIn("if ! deploy_with_live_attestation; then", self.script)
        self.assertIn("拒绝继续 A11～A14", self.script)
        self.assertIn("assert_2xx A11-live-first-hop", self.script)

    def test_场景清单与变量契约闭环(self) -> None:
        job = next(
            item
            for item in self.scenarios["capture_jobs"]
            if item["id"] == "candidate-frozen-aux"
        )
        env = job["steps"][0]["environment"]
        self.assertEqual(env["LIVE_ATTESTATION_COMPOSE_DIR"], "{live_attestation_compose_dir}")
        self.assertEqual(env["LIVE_ATTESTATION_COMPOSE_FILES"], "{live_attestation_compose_files}")
        names = {item["name"] for item in self.scenarios["variable_contract"]}
        self.assertIn("live_attestation_compose_dir", names)
        self.assertIn("live_attestation_compose_files", names)
        for item in self.scenarios["variable_contract"]:
            if item["name"].startswith("live_attestation_"):
                # 坐标不是秘密；变量合同对 preflight/validation_only 仍允许为空，
                # formal production_replacement 由建 Campaign 前的用途门禁收紧。
                self.assertFalse(item["sensitive"])
                self.assertFalse(item["required"])

    def test_工具侧同时提供参数与持久化(self) -> None:
        self.assertIn("--live-attestation-compose-dir", self.upgrade)
        self.assertIn("--live-attestation-compose-files", self.upgrade)
        self.assertIn('"live_attestation_compose_dir": str(', self.upgrade)
        self.assertIn('live_attestation_compose_dir=str(', self.upgrade)
        self.assertIn(
            "formal production_replacement 必须在建 Campaign 前冻结",
            self.upgrade,
        )

    def test_compose_文件串规范化且不使用_eval(self) -> None:
        self.assertIn("prepare_live_attestation_compose_args()", self.script)
        self.assertIn(
            'live_attestation_compose_args+=("-f" "$token")', self.script
        )
        self.assertIn(
            'docker compose "${live_attestation_compose_args[@]}"', self.script
        )
        self.assertNotIn("eval docker compose", self.script)


if __name__ == "__main__":
    unittest.main()
