"""
Image pinning at the operator's door: the pipeline, its CLI, and the LiveAWS lookups.

The arm suites (safe_agents/arms/*/tests) cover what each provisioner does with an AMI id or an
image URI. This file covers what sits in front of them:

  1. A flag that the manifest's arm does not use is an error, never ignored. So is an image flag
     given to a run that does not include the provision phase.
  2. The CLI passes exactly what was typed to run_pipeline, and defaults every override to off.
  3. The overrides are per-run switches: nothing in the manifest or the environment sets them.
  4. LiveAWS's two AMI lookups let an AWS error surface. They used to return an empty list, which
     read as "no baked AMI".

All tests are AWS-free. LiveAWS is exercised with a stub client in place of boto3.
"""
from __future__ import annotations

import ast
import dataclasses
import importlib
import logging
from pathlib import Path
from typing import Any

import pytest
import yaml

from safe_agents.pipeline import FakeAWS, LiveAWS, cli, load_manifest, run_pipeline
from safe_agents.pipeline import image_pin
from safe_agents.pipeline import pipeline as pipeline_module
from safe_agents.pipeline.image_pin import ImagePinError, check_flags_apply
from safe_agents.pipeline.manifest import DeploymentManifest
from safe_agents.pipeline.phases import provision_phase

REPO_ROOT = Path(__file__).parent.parent.parent.parent
AGENTS_DIR = REPO_ROOT / "agents"
TEST_STUB_DIR = AGENTS_DIR / "test-stub"
MANIFESTS = {
    "ec2": AGENTS_DIR / "smoke-ec2.yaml",
    "rhel-openshell": AGENTS_DIR / "smoke-rhel-openshell.yaml",
    "fargate": AGENTS_DIR / "smoke-fargate.yaml",
    "ec2-woken": AGENTS_DIR / "smoke-woken.yaml",
}

AMI_ID = "ami-0123456789abcdef0"
IMAGE_URI = f"registry.example/team/agent@sha256:{'a' * 64}"
TAGGED_IMAGE_URI = "registry.example/team/agent:v7"


def _error(result: Any) -> str:
    return result.phase_results[-1].error or ""


# ---------------------------------------------------------------------------
# 1. A flag for the wrong arm, or for a run that does not provision, is an error
# ---------------------------------------------------------------------------

_AMI_FLAGS = [({"ami_id": AMI_ID}, "--ami-id"), ({"allow_newest_ami": True}, "--allow-newest-ami")]
_IMAGE_FLAGS = [
    ({"image_uri": IMAGE_URI}, "--image-uri"),
    ({"allow_mutable_image_tag": True}, "--allow-mutable-image-tag"),
]
# (arm, the flags that do not apply to it)
_WRONG_ARM_CASES = [
    pytest.param(arm, kwargs, flag, id=f"{arm}:{flag}")
    for arm, flags in (
        ("ec2", _IMAGE_FLAGS),
        ("rhel-openshell", _IMAGE_FLAGS),
        ("fargate", _AMI_FLAGS),
        ("ec2-woken", _AMI_FLAGS + _IMAGE_FLAGS),
    )
    for kwargs, flag in flags
]


class TestFlagMustApplyToTheArm:
    @pytest.mark.parametrize("arm, kwargs, flag", _WRONG_ARM_CASES)
    @pytest.mark.parametrize("dry_run", [True, False])
    def test_wrong_arm_flag_fails_the_provision_phase(
        self, arm: str, kwargs: dict, flag: str, dry_run: bool
    ) -> None:
        aws = FakeAWS()
        result = run_pipeline(MANIFESTS[arm], dry_run=dry_run, aws=aws, **kwargs)
        assert not result.success
        assert result.aborted_at == "provision"
        assert f"{flag} does not apply to arm {arm!r}" in _error(result)
        assert "Nothing was provisioned" in _error(result)
        assert aws.calls == [], f"a refused run must touch nothing; calls: {aws.calls}"

    def test_ec2_woken_needs_no_image_flag(self) -> None:
        """The ec2-woken phase deploys the airlock and launches nothing, so it has nothing to
        pin and must not start refusing."""
        aws = FakeAWS()
        result = run_pipeline(MANIFESTS["ec2-woken"], dry_run=True, aws=aws)
        assert result.success, _error(result)

    @pytest.mark.parametrize(
        "kwargs, flag",
        _AMI_FLAGS + _IMAGE_FLAGS,
        ids=[flag for _, flag in _AMI_FLAGS + _IMAGE_FLAGS],
    )
    @pytest.mark.parametrize("phases", [("deploy",), ("smoke",), ("teardown",), ("verify",)])
    def test_image_flag_without_the_provision_phase_is_refused(
        self, kwargs: dict, flag: str, phases: tuple
    ) -> None:
        aws = FakeAWS()
        result = run_pipeline(MANIFESTS["ec2"], dry_run=True, aws=aws, phases=phases, **kwargs)
        assert not result.success
        assert result.aborted_at == "preflight"
        assert [pr.phase for pr in result.phase_results] == ["preflight"]
        assert f"{flag} is used only by the provision phase" in _error(result)
        assert aws.calls == []

    def test_check_flags_apply_passes_the_matching_flags(self) -> None:
        check_flags_apply(
            "ec2", ami_id=AMI_ID, image_uri=None,
            allow_newest_ami=False, allow_mutable_image_tag=False,
        )
        check_flags_apply(
            "fargate", ami_id=None, image_uri=TAGGED_IMAGE_URI,
            allow_newest_ami=False, allow_mutable_image_tag=True,
        )

    def test_two_wrong_flags_are_both_named(self) -> None:
        with pytest.raises(ImagePinError) as excinfo:
            check_flags_apply(
                "ec2", ami_id=AMI_ID, image_uri=TAGGED_IMAGE_URI,
                allow_newest_ami=False, allow_mutable_image_tag=True,
            )
        assert (
            "--image-uri and --allow-mutable-image-tag do not apply to arm 'ec2'"
            in str(excinfo.value)
        )

    def test_the_arm_lists_cover_every_manifest_arm(self) -> None:
        """A new arm must be placed deliberately: it either pins an AMI, pins an image, or is
        listed here as selecting neither."""
        from safe_agents.pipeline.manifest import VALID_ARMS  # noqa: PLC0415

        selects_nothing = {"ec2-woken"}
        assert image_pin.AMI_ARMS | image_pin.CONTAINER_IMAGE_ARMS | selects_nothing == VALID_ARMS
        assert not image_pin.AMI_ARMS & image_pin.CONTAINER_IMAGE_ARMS


# ---------------------------------------------------------------------------
# 2. The CLI
# ---------------------------------------------------------------------------

class _RecordingPipeline:
    """Stands in for run_pipeline: records the call, returns a result that prints nothing."""

    def __init__(self) -> None:
        self.kwargs: dict = {}

    def __call__(self, manifest_path: Path, **kwargs: Any) -> Any:
        self.kwargs = kwargs

        class _Result:
            success = True

            def print_plan(self) -> None:
                pass

        return _Result()


@pytest.fixture()
def recorded(monkeypatch: pytest.MonkeyPatch) -> _RecordingPipeline:
    recorder = _RecordingPipeline()
    monkeypatch.setattr(cli, "run_pipeline", recorder)
    return recorder


def _run_cli(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(argv)
    return int(excinfo.value.code or 0)


_IMAGE_KWARGS = ("ami_id", "image_uri", "allow_newest_ami", "allow_mutable_image_tag")


class TestCliFlags:
    @pytest.mark.parametrize(
        "argv, expected",
        [
            pytest.param([], (None, None, False, False), id="nothing"),
            pytest.param(["--ami-id", AMI_ID], (AMI_ID, None, False, False), id="ami-id"),
            pytest.param(["--image-uri", IMAGE_URI], (None, IMAGE_URI, False, False), id="image-uri"),
            pytest.param(["--allow-newest-ami"], (None, None, True, False), id="allow-newest-ami"),
            pytest.param(
                ["--image-uri", TAGGED_IMAGE_URI, "--allow-mutable-image-tag"],
                (None, TAGGED_IMAGE_URI, False, True),
                id="tag-with-override",
            ),
        ],
    )
    def test_flags_reach_run_pipeline_exactly_as_typed(
        self, recorded: _RecordingPipeline, argv: list[str], expected: tuple
    ) -> None:
        assert _run_cli([str(MANIFESTS["ec2"]), "--dry-run", *argv]) == 0
        assert tuple(recorded.kwargs[k] for k in _IMAGE_KWARGS) == expected

    def test_overrides_take_no_value(self, recorded: _RecordingPipeline, capsys: Any) -> None:
        """`--allow-newest-ami=false` must not parse as 'set'. It is a bare switch."""
        with pytest.raises(SystemExit) as excinfo:
            cli.main([str(MANIFESTS["ec2"]), "--allow-newest-ami=false"])
        assert excinfo.value.code == 2
        assert recorded.kwargs == {}
        capsys.readouterr()


@pytest.fixture()
def cli_fake_aws(monkeypatch: pytest.MonkeyPatch) -> FakeAWS:
    """Make the CLI's default AWS a FakeAWS, so no boto3 client can be built by these tests."""
    aws = FakeAWS()
    monkeypatch.setattr(pipeline_module, "LiveAWS", lambda: aws)
    return aws


class TestCliEndToEnd:
    """The real cli.main -> run_pipeline -> provision_phase path, against FakeAWS."""

    @pytest.mark.parametrize(
        "arm, phrase",
        [
            ("ec2", "ec2 arm: no AMI id was given, and there is no default"),
            ("rhel-openshell", "rhel-openshell arm: no AMI id was given, and there is no default"),
            ("fargate", "fargate arm: no image was given, and there is no default"),
        ],
    )
    @pytest.mark.parametrize("extra", [["--dry-run"], []], ids=["dry-run", "live"])
    def test_no_reference_exits_nonzero_with_the_refusal(
        self, cli_fake_aws: FakeAWS, capsys: Any, arm: str, phrase: str, extra: list[str]
    ) -> None:
        code = _run_cli([str(MANIFESTS[arm]), "--agent-dir", str(TEST_STUB_DIR), *extra])
        out = capsys.readouterr().out
        assert code == 1
        assert phrase in out
        assert "Pipeline aborted at phase 'provision'" in out
        assert "Plan OK" not in out
        assert cli_fake_aws.calls == []

    def test_dry_run_prints_the_explicit_ami(self, cli_fake_aws: FakeAWS, capsys: Any) -> None:
        code = _run_cli(
            [str(MANIFESTS["ec2"]), "--agent-dir", str(TEST_STUB_DIR), "--dry-run", "--ami-id", AMI_ID]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert f"-> ec2 arm: launch from AMI {AMI_ID}, named by the operator" in out
        assert cli_fake_aws.calls == []

    def test_dry_run_prints_the_override_and_touches_nothing(
        self, cli_fake_aws: FakeAWS, capsys: Any
    ) -> None:
        code = _run_cli(
            [
                str(MANIFESTS["rhel-openshell"]), "--agent-dir", str(TEST_STUB_DIR),
                "--dry-run", "--allow-newest-ami",
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "OVERRIDE --allow-newest-ami" in out
        assert "MARKETPLACE FALLBACK" in out
        assert cli_fake_aws.calls == []

    @pytest.mark.parametrize(
        "argv, phrase",
        [
            (["--ami-id", "ami-LATEST"], "'ami-LATEST' is not an AMI id"),
            (["--ami-id", "latest"], "'latest' is not an AMI id"),
            (["--ami-id", AMI_ID, "--allow-newest-ami"], "both an AMI id and the newest-AMI override"),
            (["--image-uri", IMAGE_URI], "--image-uri does not apply to arm 'ec2'"),
        ],
    )
    def test_bad_ami_input_is_refused_before_any_aws_call(
        self, cli_fake_aws: FakeAWS, capsys: Any, argv: list[str], phrase: str
    ) -> None:
        code = _run_cli([str(MANIFESTS["ec2"]), "--agent-dir", str(TEST_STUB_DIR), *argv])
        assert code == 1
        assert phrase in capsys.readouterr().out
        assert cli_fake_aws.calls == []

    @pytest.mark.parametrize(
        "argv, phrase",
        [
            (["--image-uri", TAGGED_IMAGE_URI], "names the image by tag"),
            (["--image-uri", "registry.example/team/agent:latest"], "names the image by tag"),
            (["--allow-mutable-image-tag"], "no image was given, and there is no default"),
            (["--image-uri", "registry.example/team/agent"], "no implicit `latest`"),
            (["--ami-id", AMI_ID, "--image-uri", IMAGE_URI], "--ami-id does not apply to arm 'fargate'"),
        ],
    )
    def test_bad_image_input_is_refused_before_any_aws_call(
        self, cli_fake_aws: FakeAWS, capsys: Any, argv: list[str], phrase: str
    ) -> None:
        code = _run_cli([str(MANIFESTS["fargate"]), *argv])
        assert code == 1
        assert phrase in capsys.readouterr().out
        assert cli_fake_aws.calls == []


# ---------------------------------------------------------------------------
# 3. The overrides are per-run switches: not the manifest, not the environment
# ---------------------------------------------------------------------------

_OVERRIDE_SPELLINGS = (
    "allow_newest_ami", "allow-newest-ami", "allowNewestAmi",
    "allow_mutable_image_tag", "allow-mutable-image-tag", "allowMutableImageTags",
)
_REFERENCE_SPELLINGS = ("ami_id", "ami-id", "image_id", "image_uri", "image-uri", "image")


def _manifest_with(tmp_path: Path, arm: str, extra: dict) -> Path:
    data = yaml.safe_load(MANIFESTS[arm].read_text(encoding="utf-8"))
    data.update(extra)
    data.setdefault("provision", {}).update(extra)
    path = tmp_path / f"{arm}.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


class TestOverridesArePerRun:
    @pytest.mark.parametrize("arm", ["ec2", "rhel-openshell", "fargate"])
    def test_manifest_keys_do_not_set_an_override_or_a_reference(
        self, tmp_path: Path, arm: str
    ) -> None:
        """Every plausible spelling, at the top level and under a `provision:` block."""
        extra: dict = {key: True for key in _OVERRIDE_SPELLINGS}
        extra.update({key: AMI_ID for key in _REFERENCE_SPELLINGS})
        path = _manifest_with(tmp_path, arm, extra)

        aws = FakeAWS()
        for dry_run in (True, False):
            result = run_pipeline(path, dry_run=dry_run, aws=aws, agent_dir=TEST_STUB_DIR)
            assert not result.success
            assert result.aborted_at == "provision"
            assert "there is no default" in _error(result)
        assert aws.calls == []

    def test_manifest_schema_has_no_image_or_override_field(self) -> None:
        """The manifest is reviewed once and reused; a per-run switch does not belong in it."""
        names = {f.name for f in dataclasses.fields(DeploymentManifest)}
        offending = {
            n for n in names if any(word in n.lower() for word in ("ami", "image", "allow"))
        }
        assert offending == set(), f"DeploymentManifest grew image/override fields: {offending}"

    @pytest.mark.parametrize("arm", ["ec2", "rhel-openshell", "fargate"])
    def test_environment_variables_do_not_set_an_override_or_a_reference(
        self, monkeypatch: pytest.MonkeyPatch, cli_fake_aws: FakeAWS, capsys: Any, arm: str
    ) -> None:
        for stem in ("ALLOW_NEWEST_AMI", "ALLOW_MUTABLE_IMAGE_TAG", "ALLOW_MUTABLE_IMAGE_TAGS"):
            for prefix in ("", "SA_", "SAFE_AGENTS_"):
                monkeypatch.setenv(prefix + stem, "true")
        for stem, value in (("AMI_ID", AMI_ID), ("IMAGE_ID", AMI_ID), ("IMAGE_URI", IMAGE_URI)):
            for prefix in ("", "SA_", "SAFE_AGENTS_"):
                monkeypatch.setenv(prefix + stem, value)

        code = _run_cli([str(MANIFESTS[arm]), "--agent-dir", str(TEST_STUB_DIR)])
        assert code == 1
        assert "there is no default" in capsys.readouterr().out
        assert cli_fake_aws.calls == []

    @pytest.mark.parametrize(
        "module_name",
        [
            "safe_agents.pipeline.image_pin",
            "safe_agents.pipeline.cli",
            "safe_agents.pipeline.pipeline",
            "safe_agents.pipeline.phases",
            "safe_agents.pipeline.manifest",
            "safe_agents.arms.ec2.provision",
            "safe_agents.arms.ec2_woken.box_provision",
            "safe_agents.arms.rhel_openshell.provision",
            "safe_agents.arms.fargate.provision",
        ],
    )
    def test_the_door_does_not_read_the_environment(self, module_name: str) -> None:
        """Structural, because no list of variable names can be complete: the modules that
        carry the flags from the command line to RunInstances / RegisterTaskDefinition never
        touch os.environ."""
        module = importlib.import_module(module_name)
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree) if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            (node.module or "").split(".")[0]
            for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.level == 0
        }
        assert "os" not in imported, f"{module_name} imports os"
        names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | {
            n.id for n in ast.walk(tree) if isinstance(n, ast.Name)
        }
        assert not names & {"environ", "getenv"}, f"{module_name} reads the environment"

    @pytest.mark.parametrize("value", ["true", "false", 1, 0, None, "1"])
    def test_an_override_must_be_a_real_bool(self, value: Any) -> None:
        """A caller that lifts the switch from a config file or an env var gets a string. A
        truthy string, `"false"` included, must not switch the override on."""
        manifest = load_manifest(MANIFESTS["ec2"])
        aws = FakeAWS()
        result = provision_phase(
            manifest, aws, dry_run=False, environment="development", allow_newest_ami=value
        )
        assert not result.success
        assert "allow_newest_ami must be True or False" in result.error
        assert aws.calls == []


# ---------------------------------------------------------------------------
# 4. LiveAWS: a failed lookup is a failure, never an empty result
# ---------------------------------------------------------------------------

class _DeniedEc2Client:
    """Stands in for the boto3 EC2 client. Every DescribeImages call fails."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def describe_images(self, **kwargs: Any) -> dict:
        self.calls.append(kwargs)
        raise PermissionError(
            "An error occurred (UnauthorizedOperation) when calling the DescribeImages operation"
        )


class _Ec2ClientReturning:
    def __init__(self, images: list[dict]) -> None:
        self._images = images

    def describe_images(self, **kwargs: Any) -> dict:
        return {"Images": self._images}


def _live_with(client: Any) -> LiveAWS:
    live = LiveAWS()
    live._ec2 = client  # the lazy factory returns this instead of building a boto3 client
    return live


class TestLiveLookupsSurfaceErrors:
    @pytest.mark.parametrize(
        "call",
        [
            pytest.param(lambda aws: aws.describe_images({"safe-agents:ami": "base"}), id="describe_images"),
            pytest.param(
                lambda aws: aws.describe_images_by_owner_name("309956199498", "RHEL-9.*"),
                id="describe_images_by_owner_name",
            ),
        ],
    )
    def test_an_aws_error_propagates(self, call: Any, caplog: pytest.LogCaptureFixture) -> None:
        client = _DeniedEc2Client()
        with caplog.at_level(logging.WARNING):
            with pytest.raises(PermissionError, match="UnauthorizedOperation"):
                call(_live_with(client))
        assert len(client.calls) == 1

    def test_an_empty_answer_is_still_an_empty_list(self) -> None:
        live = _live_with(_Ec2ClientReturning([]))
        assert live.describe_images({"safe-agents:ami": "base"}) == []
        assert live.describe_images_by_owner_name("309956199498", "RHEL-9.*") == []

    def test_a_denied_baked_lookup_cannot_cause_the_rhel_marketplace_fallback(self) -> None:
        """The end-to-end shape of the old bug: LiveAWS swallowed the error, the RHEL arm read
        the empty list as 'no bake', and launched Red Hat's image with only a warning."""
        from safe_agents.arms.rhel_openshell.provision import resolve_base_ami  # noqa: PLC0415

        client = _DeniedEc2Client()
        with pytest.raises(PermissionError, match="UnauthorizedOperation"):
            resolve_base_ami(_live_with(client), allow_newest_ami=True)
        # One call, the self-owned lookup. The marketplace lookup never ran.
        assert [c["Owners"] for c in client.calls] == [["self"]]

    def test_bake_teardown_no_longer_reads_a_failed_lookup_as_nothing_to_remove(self) -> None:
        """The other caller of describe_images. With the error swallowed, a teardown that could
        not list AMIs reported none to deregister."""
        from safe_agents.arms.ec2.ami.teardown import _teardown_amis  # noqa: PLC0415

        report: dict = {"amis_deregistered": [], "amis_already_gone": []}
        with pytest.raises(PermissionError, match="UnauthorizedOperation"):
            _teardown_amis(_live_with(_DeniedEc2Client()), {"safe-agents:ami": "base"}, report)
