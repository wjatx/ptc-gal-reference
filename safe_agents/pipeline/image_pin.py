"""
Image pinning for the provisioners: the one place an AMI id or a container image reference is
accepted or refused.

This is the Python half of ``infra/lib/image-pin.ts``. The CDK app deploys every image by digest
and refuses a tag without an override; the provisioners and the pipeline CLI follow the same rule
for the two things they choose: the AMI an instance launches from, and the container image a task
definition names.

The rules:
  - The operator names the exact thing. An AMI by id (``--ami-id``, ``image_id=``), a container
    image by digest (``--image-uri <repository-uri>@sha256:<64 hex>``, ``image_uri=``).
  - With nothing named, provisioning refuses before any AWS call. There is no default.
  - "Newest AMI by tag" runs only under ``--allow-newest-ami`` (``allow_newest_ami=True``). A tag
    in ``--image-uri`` is accepted only with ``--allow-mutable-image-tag``
    (``allow_mutable_image_tag=True``). There is no implicit ``latest`` under any flag.
  - An override is recorded: one WARNING line naming what was chosen and the rule that chose it,
    and the same line as a step in the pipeline plan.
  - The overrides are per-run switches. They are parameters of a call and flags of a command.
    Nothing here reads the manifest or the environment for them, and a value that is not a real
    ``bool`` is refused, so a string such as ``"false"`` lifted from a config file cannot switch
    one on.

Every refusal is an ``ImagePinError``. It subclasses ``RuntimeError`` because the pipeline phases
already report a provisioner's ``RuntimeError`` as a failed phase with its message.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Mapping, Optional

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

AMI_ID_FLAG = "--ami-id"
IMAGE_URI_FLAG = "--image-uri"
ALLOW_NEWEST_AMI_FLAG = "--allow-newest-ami"
ALLOW_MUTABLE_IMAGE_TAG_FLAG = "--allow-mutable-image-tag"

KIND_AMI = "ami"
KIND_CONTAINER_IMAGE = "container-image"

# How a reference came to be chosen. Only the first is the normal path.
SOURCE_EXPLICIT = "explicit"
SOURCE_NEWEST_BY_TAG = "newest-by-tag"
SOURCE_MARKETPLACE_FALLBACK = "marketplace-fallback"
SOURCE_MUTABLE_TAG = "mutable-tag"

# Which manifest arms the pipeline's provision phase selects an image for. The ec2-woken phase
# deploys the airlock stack and launches nothing; its box is launched by the library function
# ec2_woken_box_provision, which takes image_id= directly.
AMI_ARMS: frozenset[str] = frozenset({"ec2", "rhel-openshell"})
CONTAINER_IMAGE_ARMS: frozenset[str] = frozenset({"fargate"})

# "ami-" plus 8 hex characters (the original id length) or 17 (the current one).
_AMI_ID_PATTERN = re.compile(r"^ami-(?:[0-9a-f]{8}|[0-9a-f]{17})$")
_DIGEST_SUFFIX_PATTERN = re.compile(r"@sha256:[0-9a-f]{64}$")
# The OCI distribution tag grammar, as in infra/lib/image-pin.ts.
_TAG_PATTERN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")

_AMI_ID_FORM = 'An AMI id is "ami-" followed by 8 or 17 lowercase hexadecimal characters.'
_DIGEST_FORM = (
    'A digest reference ends in "@sha256:" followed by exactly 64 lowercase hexadecimal '
    "characters."
)
_IMAGE_OVERRIDE_IS_RECORDED = (
    "The override logs the image and its tag at WARNING, and the pipeline plan records the same "
    "line."
)


class ImagePinError(RuntimeError):
    """Provisioning refused an AMI or container image reference, or the lack of one."""


# ---------------------------------------------------------------------------
# The record of a choice
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ImageSelection:
    """What a provisioner will launch or run, and how it came to be chosen."""

    arm: str
    kind: str        # KIND_AMI | KIND_CONTAINER_IMAGE
    reference: str   # the AMI id, or the full image URI
    source: str      # one of the SOURCE_* values
    # Set only when an override chose the reference:
    rule: Optional[str] = None      # the rule that chose it, in words
    override: Optional[str] = None  # the switch that permitted it, as the caller spells it
    pin_hint: Optional[str] = None  # what to pass next time to name it explicitly

    @property
    def is_override(self) -> bool:
        return self.source != SOURCE_EXPLICIT

    def describe(self) -> str:
        """One line stating the choice. The WARNING log and the plan step are both this line."""
        if self.kind == KIND_AMI:
            if self.source == SOURCE_EXPLICIT:
                return f"{self.arm}: launch from AMI {self.reference}, named by the operator"
            fallback = (
                "MARKETPLACE FALLBACK: this is a vendor marketplace image, not one this account "
                "baked. "
                if self.source == SOURCE_MARKETPLACE_FALLBACK
                else ""
            )
            return (
                f"{self.arm}: OVERRIDE {self.override}: launch from AMI {self.reference}, which "
                f"the operator did not name. {fallback}Rule that chose it: {self.rule}. A tag "
                "can be edited and a newer image can appear, so what launches may not be what "
                f"was reviewed. Pass {self.pin_hint} to pin it."
            )
        if self.source == SOURCE_EXPLICIT:
            return f"{self.arm}: task definition image {self.reference}, pinned by digest"
        return (
            f"{self.arm}: OVERRIDE {self.override}: task definition image {self.reference} is "
            f"named by {self.rule}. A tag can be moved, so what runs may not be what was "
            f"reviewed. Pass {self.pin_hint} to pin it."
        )


def record_override(logger: logging.Logger, selection: ImageSelection) -> None:
    """Log an override at WARNING. A reference the operator named is not logged here."""
    if selection.is_override:
        logger.warning("%s", selection.describe())


def _require_bool(value: object, parameter: str) -> bool:
    """An override is a real bool. A truthy string from a config file must not switch it on."""
    if not isinstance(value, bool):
        raise ImagePinError(
            f"{parameter} must be True or False, got {value!r}. The override is a per-run "
            "switch passed by the caller; it is not read from a manifest or the environment."
        )
    return value


# ---------------------------------------------------------------------------
# AMIs
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AmiPinSpec:
    """Per-arm facts the AMI messages need."""

    arm: str                       # what the messages call it, e.g. "ec2 arm"
    entry_point: str               # the provisioner function, e.g. "ec2_provision"
    tag_filter: Mapping[str, str]  # the bakery tag, e.g. {"safe-agents:ami": "base"}
    newest_rule: str               # what the override does, in words
    bake_readme: str               # where the bake and its output are documented
    fallback_rule: Optional[str] = None  # a second rule tried when the first finds nothing
    has_cli: bool = True           # False for a library-only entry point

    def list_command(self) -> str:
        """The command that lists this arm's baked AMIs."""
        filters = " ".join(
            f'"Name=tag:{key},Values={value}"' for key, value in self.tag_filter.items()
        )
        return (
            f"aws ec2 describe-images --owners self --filters {filters} "
            "--query 'Images[].[ImageId,CreationDate,Name]' --output table"
        )

    def explicit_hint(self, image_id: str = "<ami-id>") -> str:
        if self.has_cli:
            return (
                f"{AMI_ID_FLAG} {image_id} (image_id= when calling {self.entry_point} directly)"
            )
        return f'image_id="{image_id}" to {self.entry_point}'

    def override_hint(self) -> str:
        if self.has_cli:
            return f"{ALLOW_NEWEST_AMI_FLAG} (allow_newest_ami=True)"
        return f"allow_newest_ami=True to {self.entry_point}"

    def how_to_get_an_id(self) -> str:
        return (
            f"The id is the output of the bake ({self.bake_readme}), or list the baked AMIs "
            f"with `{self.list_command()}`."
        )

    def override_is_recorded(self) -> str:
        recorded = "The override logs the AMI it chose and the rule that chose it at WARNING"
        if self.has_cli:
            return f"{recorded}, and the pipeline plan records the same line."
        return f"{recorded}."


def _validate_ami_id(spec: AmiPinSpec, image_id: object) -> str:
    if not isinstance(image_id, str) or not _AMI_ID_PATTERN.match(image_id):
        raise ImagePinError(
            f"{spec.arm}: {image_id!r} is not an AMI id. {_AMI_ID_FORM} "
            f"{spec.how_to_get_an_id()}"
        )
    return image_id


def explicit_ami(
    spec: AmiPinSpec, image_id: Optional[str], allow_newest_ami: bool
) -> Optional[ImageSelection]:
    """Decide the AMI without touching AWS.

    Returns the selection when the operator named an AMI. Returns None when the override is set
    and the caller must run its lookup. Raises ImagePinError for every other input: nothing
    named, a malformed id, or an id together with the override.
    """
    allow = _require_bool(allow_newest_ami, "allow_newest_ami")
    if image_id is not None and allow:
        raise ImagePinError(
            f"{spec.arm}: both an AMI id and the newest-AMI override were given. Pass "
            f"exactly one: {spec.explicit_hint()} (the normal path), or {spec.override_hint()}."
        )
    if image_id is not None:
        return ImageSelection(
            arm=spec.arm,
            kind=KIND_AMI,
            reference=_validate_ami_id(spec, image_id),
            source=SOURCE_EXPLICIT,
        )
    if allow:
        return None
    raise ImagePinError(
        f"{spec.arm}: no AMI id was given, and there is no default. Picking the newest AMI "
        "by tag would launch whatever was baked or tagged last, which may not be the image that "
        f"was reviewed. Pass {spec.explicit_hint()}. {spec.how_to_get_an_id()} To launch the "
        f"newest AMI by tag anyway, pass {spec.override_hint()}. {spec.override_is_recorded()}"
    )


def newest_ami(spec: AmiPinSpec, image_id: str, *, fallback: bool = False) -> ImageSelection:
    """The selection for an AMI an override lookup chose."""
    if fallback and spec.fallback_rule is None:
        raise ValueError(f"{spec.arm} declares no fallback rule")
    return ImageSelection(
        arm=spec.arm,
        kind=KIND_AMI,
        reference=image_id,
        source=SOURCE_MARKETPLACE_FALLBACK if fallback else SOURCE_NEWEST_BY_TAG,
        rule=spec.fallback_rule if fallback else spec.newest_rule,
        override=spec.override_hint(),
        pin_hint=spec.explicit_hint(image_id),
    )


def plan_ami(spec: AmiPinSpec, image_id: Optional[str], allow_newest_ami: bool) -> str:
    """The dry-run plan line for the AMI. Raises ImagePinError where a real run would refuse."""
    selection = explicit_ami(spec, image_id, allow_newest_ami)
    if selection is not None:
        return selection.describe()
    fallback = (
        f" If that finds nothing: MARKETPLACE FALLBACK, a vendor marketplace image and not one "
        f"this account baked, chosen by: {spec.fallback_rule}."
        if spec.fallback_rule
        else ""
    )
    return (
        f"{spec.arm}: OVERRIDE {spec.override_hint()}: the AMI is chosen when provisioning "
        f"runs and is not named by the operator. Rule: {spec.newest_rule}.{fallback} A dry run "
        "makes no AWS call, so the id is not known here; the real run logs it at WARNING and "
        f"records it in its plan. Pass {spec.explicit_hint()} to pin it."
    )


# ---------------------------------------------------------------------------
# Container images
# ---------------------------------------------------------------------------

def _how_to_get_a_digest(environment: str) -> str:
    return (
        "Read the digest back after pushing the image: "
        "`podman push --digestfile <file> <image> <repository-uri>:<unique tag>` writes it to "
        "<file>, or `aws ecr describe-images --repository-name <repository-name> --image-ids "
        "imageTag=<tag> --query 'imageDetails[0].imageDigest' --output text` prints it. The "
        f"repository URI is the SSM parameter /safe-agents/{environment}/ecr-agent-repo-uri."
    )


def select_container_image(
    arm: str,
    entry_point: str,
    image_uri: Optional[str],
    allow_mutable_image_tag: bool,
    *,
    environment: str,
) -> ImageSelection:
    """Decide the container image. Pure: no AWS call, and the same answer in a dry run.

    Accepts a digest reference. Accepts a tag reference only with the override. Refuses a
    missing reference, a reference with neither a digest nor a tag, a malformed digest, and the
    override alongside a digest.
    """
    allow = _require_bool(allow_mutable_image_tag, "allow_mutable_image_tag")
    explicit_hint = (
        f"{IMAGE_URI_FLAG} <repository-uri>@sha256:<64 lowercase hex characters> "
        f"(image_uri= when calling {entry_point} directly)"
    )
    override_hint = (
        f"{IMAGE_URI_FLAG} <repository-uri>:<tag> together with "
        f"{ALLOW_MUTABLE_IMAGE_TAG_FLAG} (allow_mutable_image_tag=True)"
    )
    how = _how_to_get_a_digest(environment)

    if image_uri is None:
        raise ImagePinError(
            f"{arm}: no image was given, and there is no default. A default tag such as "
            "`latest` points at whatever was pushed last, which may not be the image that was "
            f"reviewed. Pass {explicit_hint}. {how} To name the image by tag anyway, pass "
            f"{override_hint}. {_IMAGE_OVERRIDE_IS_RECORDED}"
        )
    if not isinstance(image_uri, str) or not image_uri or any(c.isspace() for c in image_uri):
        raise ImagePinError(
            f"{arm}: {image_uri!r} is not an image reference. Pass {explicit_hint}. {how}"
        )

    repository, at, _ = image_uri.partition("@")
    if at:
        if not repository or not _DIGEST_SUFFIX_PATTERN.search(image_uri):
            raise ImagePinError(
                f"{arm}: {image_uri!r} is not a digest reference. {_DIGEST_FORM} {how}"
            )
        if allow:
            raise ImagePinError(
                f"{arm}: {ALLOW_MUTABLE_IMAGE_TAG_FLAG} was passed, but the image is named "
                "by digest. Drop the override: one that changes nothing should not appear in "
                "the record of a run."
            )
        return ImageSelection(
            arm=arm, kind=KIND_CONTAINER_IMAGE, reference=image_uri, source=SOURCE_EXPLICIT
        )

    # No digest. The tag, if any, follows the last ":" of the last path component; a ":" earlier
    # than that is a registry port.
    name, colon, tag = image_uri.rpartition("/")[2].rpartition(":")
    if not colon:
        raise ImagePinError(
            f"{arm}: {image_uri!r} names neither a digest nor a tag, and a reference with "
            "neither means `latest`. There is no implicit `latest` under any flag. Pass "
            f"{explicit_hint}. {how}"
        )
    if not allow:
        raise ImagePinError(
            f"{arm}: {image_uri!r} names the image by tag, and a tag can be moved to a "
            f"different image after it was reviewed. Pass {explicit_hint} instead. {how} To "
            f"provision by tag anyway, add {ALLOW_MUTABLE_IMAGE_TAG_FLAG} "
            f"(allow_mutable_image_tag=True). {_IMAGE_OVERRIDE_IS_RECORDED}"
        )
    if not name or not _TAG_PATTERN.match(tag):
        raise ImagePinError(
            f"{arm}: {image_uri!r} does not end in an image tag. A tag is 1 to 128 "
            'characters from letters, digits, "_", "." and "-", and does not start with "." or '
            '"-".'
        )
    return ImageSelection(
        arm=arm,
        kind=KIND_CONTAINER_IMAGE,
        reference=image_uri,
        source=SOURCE_MUTABLE_TAG,
        rule=f'tag "{tag}", which the registry resolves each time a task starts',
        override=f"{ALLOW_MUTABLE_IMAGE_TAG_FLAG} (allow_mutable_image_tag=True)",
        pin_hint=f"{IMAGE_URI_FLAG} <repository-uri>@sha256:<digest>",
    )


# ---------------------------------------------------------------------------
# The operator's door: which flag applies to which arm
# ---------------------------------------------------------------------------

def check_flags_apply(
    arm: str,
    *,
    ami_id: Optional[str],
    image_uri: Optional[str],
    allow_newest_ami: bool,
    allow_mutable_image_tag: bool,
) -> None:
    """Refuse a flag that the manifest's arm does not use. A flag is never silently ignored."""
    given_ami = [
        flag
        for flag, value in ((AMI_ID_FLAG, ami_id is not None), (ALLOW_NEWEST_AMI_FLAG, allow_newest_ami))
        if value
    ]
    given_image = [
        flag
        for flag, value in (
            (IMAGE_URI_FLAG, image_uri is not None),
            (ALLOW_MUTABLE_IMAGE_TAG_FLAG, allow_mutable_image_tag),
        )
        if value
    ]
    if arm in AMI_ARMS:
        wrong, uses = given_image, f"launches an instance from an AMI: pass {AMI_ID_FLAG} <ami-id>"
    elif arm in CONTAINER_IMAGE_ARMS:
        wrong, uses = given_ami, (
            f"runs a container image: pass {IMAGE_URI_FLAG} <repository-uri>@sha256:<digest>"
        )
    else:
        wrong, uses = given_ami + given_image, (
            "selects no AMI and no container image in the pipeline's provision phase"
        )
    if wrong:
        raise ImagePinError(
            f"{' and '.join(wrong)} {'does' if len(wrong) == 1 else 'do'} not apply to arm "
            f"{arm!r}, which {uses}. Nothing was provisioned."
        )
