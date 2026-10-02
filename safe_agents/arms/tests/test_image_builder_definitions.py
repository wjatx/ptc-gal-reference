"""The shipped Image Builder definitions for the two AMI-baking arms.

Both arms keep the same five files under `ami/image-builder/`. These tests hold what
is true of both: the files parse, the scheduled bake ships disabled, the component
and recipe versions agree everywhere they are written, the recipe's parent image and
the runbook's create-component command have a form Image Builder accepts, and every
component step is shell that parses.

Nothing here talks to AWS, and nothing here is evidence that a bake works.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from safe_agents.broker.tests.platform_marks import requires_posix_bash

ARMS_DIR = Path(__file__).resolve().parents[1]
JSON_FILES = ("recipe-base.json", "infra-config.json", "dist-config.json", "pipeline.json")
SEMANTIC_VERSION_FLAG = re.compile(r"--semantic-version (\d+\.\d+\.\d+)")

# An Image Builder image ARN: ...:image/<name>/<version>, optionally /<build version>.
IMAGE_ARN = re.compile(
    r"arn:[^:\s]+:imagebuilder:[^:\s]+:[^:\s]+:image/"
    r"(?P<name>[^/\s`]+)/(?P<version>[^/\s`]+)(?:/(?P<build>[^\s`]+))?"
)
VERSION_WILDCARD = "x"

# The Image Builder CreateComponent API takes the component document inline in its `data`
# parameter, and the API reference gives that parameter a maximum length of 16000.
# `aws imagebuilder create-component --data file://...` sends the file as `data`. A larger
# document is uploaded to S3 and named with `uri` instead. The reference states no unit, so
# the file is measured in UTF-8 bytes here, the larger of the two readings.
CREATE_COMPONENT_INLINE_DATA_LIMIT = 16_000
# The same API reference, on `uri`: content "up to your service quota for component size,
# which is 64 KB by default". Read as 64,000 bytes, the smaller reading.
CREATE_COMPONENT_URI_DEFAULT_QUOTA = 64_000
CREATE_COMPONENT = "aws imagebuilder create-component"
# The key a component over the inline limit is uploaded to: <recipe name>-<version>.yaml.
COMPONENT_UPLOAD_KEY = re.compile(
    r"image-builder-components/([a-z0-9-]+?)-(\d+\.\d+\.\d+)\.yaml"
)

arms = pytest.mark.parametrize("arm", ["ec2", "rhel_openshell"])


def _ami_dir(arm: str) -> Path:
    return ARMS_DIR / arm / "ami"


def _load(arm: str, name: str) -> dict:
    return json.loads((_ami_dir(arm) / "image-builder" / name).read_text(encoding="utf-8"))


def _component_text(arm: str) -> str:
    return (_ami_dir(arm) / "image-builder" / "component-base.yaml").read_text(encoding="utf-8")


def _component_commands(arm: str) -> list[tuple[str, str]]:
    """(step name, command) for every command of every step, in file order."""
    component = yaml.safe_load(_component_text(arm))
    return [
        (f"{phase['name']}/{step['name']}", str(command))
        for phase in component["phases"]
        for step in phase["steps"]
        for command in step["inputs"]["commands"]
    ]


@arms
@pytest.mark.parametrize("name", JSON_FILES)
def test_json_definition_parses(arm, name):
    assert isinstance(_load(arm, name), dict)


@arms
def test_component_has_a_build_and_a_validate_phase(arm):
    component = yaml.safe_load(_component_text(arm))
    assert component["schemaVersion"] == 1.0
    assert {"build", "validate"} <= {phase["name"] for phase in component["phases"]}
    assert _component_commands(arm), "the component has no commands"


@arms
def test_the_scheduled_bake_ships_disabled(arm):
    """A bake is a deliberate act. A pipeline that rebakes on a timer changes what a
    provision run under --allow-newest-ami picks up, and adds unreviewed images to the
    set the bake tag lists, without anyone deciding to. The schedule text stays, so an
    operator can turn it on in their own account."""
    pipeline = _load(arm, "pipeline.json")
    assert pipeline["status"] == "DISABLED", (
        f"{arm}: the shipped pipeline must be DISABLED, got {pipeline['status']!r}. "
        "Start a bake by hand with `aws imagebuilder start-image-pipeline-execution`."
    )
    assert pipeline["schedule"]["scheduleExpression"].startswith("cron("), (
        f"{arm}: keep the schedule expression; only the status ships off"
    )


@arms
def test_the_readme_says_the_schedule_ships_off_and_how_to_bake_by_hand(arm):
    readme = (_ami_dir(arm) / "README.md").read_text(encoding="utf-8")
    assert '"status": "DISABLED"' in readme
    assert "start-image-pipeline-execution" in readme


@arms
def test_component_and_recipe_versions_agree_everywhere(arm):
    """Image Builder refuses to re-create a semantic version with different content, so
    a changed component gets a new version, and every place that writes it must move
    together: the recipe, the ARNs that name it, and the two create-component commands
    a reader copies (the component header and the README)."""
    recipe = _load(arm, "recipe-base.json")
    pipeline = _load(arm, "pipeline.json")

    recipe_version = recipe["semanticVersion"]
    assert pipeline["imageRecipeArn"].endswith(f"image-recipe/{recipe['name']}/{recipe_version}")

    component_arns = [component["componentArn"] for component in recipe["components"]]
    assert len(component_arns) == 1
    component_version = component_arns[0].rsplit("/", 1)[1]
    assert component_arns[0].endswith(f"component/{recipe['name']}/{component_version}")

    for where, text in (
        ("component-base.yaml", _component_text(arm)),
        ("README.md", (_ami_dir(arm) / "README.md").read_text(encoding="utf-8")),
    ):
        assert SEMANTIC_VERSION_FLAG.findall(text) == [component_version], (
            f"{arm}: {where} must give exactly one --semantic-version, {component_version}, "
            "to match the recipe's componentArn"
        )


def test_the_rhel_recipe_keeps_the_ssm_agent_in_the_image():
    """A RHEL parent has no SSM agent. Image Builder installs one to run the build and
    removes it before it creates the AMI, unless the recipe says to leave it. The component's
    own install step finds the package present and does nothing, so without this setting the
    baked image has no agent and the box cannot be reached in a subnet with no egress. The
    first bake (2026-10-02) produced exactly that image. The Amazon Linux parent ships the
    agent, so Image Builder installs nothing there and removes nothing."""
    recipe = _load("rhel_openshell", "recipe-base.json")
    agent = recipe.get("additionalInstanceConfiguration", {}).get("systemsManagerAgent", {})
    assert agent.get("uninstallAfterBuild") is False, (
        "rhel_openshell recipe must set additionalInstanceConfiguration.systemsManagerAgent."
        "uninstallAfterBuild to false, or Image Builder removes the agent from the image"
    )
    component = _component_text("rhel_openshell")
    assert "uninstallAfterBuild" in component, (
        "the component's InstallSSMAgent step must say that the recipe setting is what keeps "
        "the agent, so nobody reads the step as sufficient"
    )


def _build_version_follows_a_wildcard(image: str) -> bool:
    """True for a parent image `create-image-recipe` refuses: an Image Builder image ARN
    whose version has a wildcard node and is followed by a build version."""
    match = IMAGE_ARN.fullmatch(image)
    if match is None:
        return False
    return VERSION_WILDCARD in match["version"].split(".") and match["build"] is not None


@pytest.mark.parametrize(
    "image, refused",
    [
        pytest.param(
            "arn:aws:imagebuilder:${AWS_REGION}:aws:image/amazon-linux-2023-arm64/x.x.x/1",
            True,
            id="the-form-refused-on-2026-10-02",
        ),
        pytest.param(
            "arn:aws:imagebuilder:us-east-1:aws:image/amazon-linux-2023-arm64/2023.x.x/1",
            True,
            id="one-wildcard-node-is-a-wildcard",
        ),
        pytest.param(
            "arn:aws:imagebuilder:${AWS_REGION}:aws:image/amazon-linux-2023-arm64/x.x.x",
            False,
            id="the-form-accepted-on-2026-10-02",
        ),
        pytest.param("${RHEL9_PARENT_AMI}", False, id="an-ami-placeholder"),
        pytest.param("ami-0123456789abcdef0", False, id="an-ami-id"),
    ],
)
def test_the_wildcard_rule_tells_the_refused_form_from_the_accepted_one(image, refused):
    assert _build_version_follows_a_wildcard(image) is refused


@arms
def test_recipe_parent_image_has_no_build_version_after_a_wildcard(arm):
    """`create-image-recipe` refused `.../amazon-linux-2023-arm64/x.x.x/1` ("The supplied
    image identifier is not in a supported format") and accepted `.../x.x.x`. A wildcard
    version names no single image, so no build version can follow it. The README is
    held to the same rule, since it is where an operator copies the ARN from."""
    parent = _load(arm, "recipe-base.json")["parentImage"]
    assert not _build_version_follows_a_wildcard(parent), (
        f"{arm}: recipe parentImage {parent!r} puts a build version after a wildcard "
        "version. Image Builder refuses that form; end the ARN at the version."
    )
    readme = (_ami_dir(arm) / "README.md").read_text(encoding="utf-8")
    bad = [m.group(0) for m in IMAGE_ARN.finditer(readme) if _build_version_follows_a_wildcard(m.group(0))]
    assert not bad, f"{arm}: README.md gives an image ARN Image Builder refuses: {bad}"


def test_the_ec2_parent_image_is_a_managed_image_arn_ending_at_a_wildcard_version():
    """Guards the test above against passing because the ARN stopped being recognized."""
    match = IMAGE_ARN.fullmatch(_load("ec2", "recipe-base.json")["parentImage"])
    assert match is not None, "the EC2 recipe's parentImage is an Image Builder image ARN"
    assert (match["name"], match["version"], match["build"]) == (
        "amazon-linux-2023-arm64", "x.x.x", None,
    )


def _create_component_commands(text: str) -> list[str]:
    """Every create-component command in a document, continuation lines joined. Reads the
    README's shell block and the component's commented header alike."""
    commands: list[str] = []
    open_command = False
    for raw in text.splitlines():
        line = raw.lstrip("# ").rstrip()
        if open_command:
            commands[-1] += " " + line.rstrip("\\").strip()
        elif line.startswith(CREATE_COMPONENT):
            commands.append(line.rstrip("\\").strip())
        else:
            continue
        open_command = line.endswith("\\")
    return commands


@arms
def test_a_component_over_the_inline_limit_is_created_from_s3(arm):
    """`create-component --data` refused the RHEL component: it is over the inline limit.
    Uploading it and passing `--uri` worked. So a runbook command may use `--data` only
    for a component that fits. The comments in the component record invariants and stay,
    so the fix for an oversize file is `--uri`, and never a smaller file."""
    component = _component_text(arm)
    size = len(component.encode("utf-8"))
    recipe = _load(arm, "recipe-base.json")
    component_version = recipe["components"][0]["componentArn"].rsplit("/", 1)[1]

    for where, text in (
        ("README.md", (_ami_dir(arm) / "README.md").read_text(encoding="utf-8")),
        ("component-base.yaml", component),
    ):
        commands = _create_component_commands(text)
        assert len(commands) == 1, f"{arm}: {where} must give one create-component command"
        flags = commands[0].split()
        inline, from_s3 = "--data" in flags, "--uri" in flags
        assert inline != from_s3, (
            f"{arm}: {where} must pass the component by exactly one of --data and --uri"
        )
        if size > CREATE_COMPONENT_INLINE_DATA_LIMIT:
            assert from_s3, (
                f"{arm}: component-base.yaml is {size} bytes, over the "
                f"{CREATE_COMPONENT_INLINE_DATA_LIMIT} that create-component accepts through "
                f"--data, and {where} passes it with --data. Upload it and pass --uri."
            )
        if from_s3:
            assert size <= CREATE_COMPONENT_URI_DEFAULT_QUOTA, (
                f"{arm}: component-base.yaml is {size} bytes, over the default "
                f"{CREATE_COMPONENT_URI_DEFAULT_QUOTA}-byte quota for a component passed by --uri"
            )
            keys = COMPONENT_UPLOAD_KEY.findall(text)
            assert keys and set(keys) == {(recipe["name"], component_version)}, (
                f"{arm}: {where} must upload the component to image-builder-components/"
                f"{recipe['name']}-{component_version}.yaml and name no other key, got {keys}"
            )


def _all_commands() -> list:
    return [
        pytest.param(command, id=f"{arm}:{step}:{index}")
        for arm in ("ec2", "rhel_openshell")
        for index, (step, command) in enumerate(_component_commands(arm))
    ]


@requires_posix_bash
@pytest.mark.parametrize("command", _all_commands())
def test_every_component_command_is_shell_that_parses(command):
    """Image Builder runs each command with bash. A quoting slip in a long inline fetch
    would otherwise surface twenty minutes into a bake."""
    done = subprocess.run(["bash", "-n"], input=command, capture_output=True, text=True)
    assert done.returncode == 0, f"bash -n failed: {done.stderr}\n{command}"
