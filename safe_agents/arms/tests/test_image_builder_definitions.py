"""The shipped Image Builder definitions for the two AMI-baking arms.

Both arms keep the same five files under `ami/image-builder/`. These tests hold what
is true of both: the files parse, the scheduled bake ships disabled, the component
and recipe versions agree everywhere they are written, and every component step is
shell that parses.

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
    later provision picks up (the newest AMI by tag) without anyone deciding to. The
    schedule text stays, so an operator can turn it on in their own account."""
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
