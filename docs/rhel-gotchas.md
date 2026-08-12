# RHEL 9 / systemd known gotchas

Hard-won lessons from building and live-testing the RHEL substrate (the `rhel-openshell`
arm and its interactive/dev-box profile). Capture here so future arm work doesn't
rediscover them. Most surfaced only in live deploys, not unit tests.

## SELinux: system services cannot exec files under `/home` (203/EXEC)

A systemd **system** service running `ExecStart=/home/<user>/...` fails with `status=203/EXEC`:
SELinux denies the `init_t` domain from executing `user_home_t` files. Two fixes:

- Put exec'd scripts under `/opt` (`opt_t`) or `/usr/local/bin` (`bin_t`), **not** `/home`.
- Or run the unit as a systemd **user** service (`~/.config/systemd/user/`), whose manager
  is unconfined and may exec from `/home`. This is why interactive-profile units
  (Remote Control, resource-watch) are user services, not system services.

## SELinux: units `mv`'d from `/tmp` won't load ("Unit file does not exist")

Writing a unit to a tmpfile then `sudo mv` into `/etc/systemd/system/` preserves the
source `tmp_t` context. systemd (PID 1) refuses to read it and reports the misleading
`Unit file <name>.timer does not exist` even though the file is present. Fix: run
`restorecon -F <unit>` after placing it, before `systemctl daemon-reload`. (Writing in
place via `sudo tee` also gets the right context.)

## `/usr/local/bin` is absent from the RHEL login-shell PATH

`aws`, `openshell`, and the AWS CLI v2 install to `/usr/local/bin`, which RHEL login shells
do not include. Every box-side script must `export PATH=/usr/local/bin:$PATH` first, or
commands fail with "command not found" even after a successful install.

## cgroups v2 controller delegation must precede the user manager's first start

Rootless podman / OpenShell sandbox creation fails with `controller 'cpu' is not available`
unless `Delegate=cpu cpuset io memory pids` is configured on `user@.service` **before** the
target user's systemd manager first starts. Set it in the root pre-bootstrap (cloud-init),
before `useradd`. Do **not** `systemctl restart user@<uid>` mid-bootstrap — it kills the
running bootstrap session.

## Rootless podman / OpenShell RPMs require sudo; linger required

OpenShell's `.fc44` RPMs install fine on RHEL 9 (glibc 2.34 is sufficient — a "too old"
error is a red herring) **but only with sudo**. Run the installer as a user with NOPASSWD
sudo (the `dev` user). Enable `loginctl enable-linger dev` so the user manager + rootless
podman socket start at boot without an active login. Under `sudo -u dev`, also export
`XDG_RUNTIME_DIR=/run/user/$(id -u)` and `DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus`
or `systemctl --user` fails with "Failed to connect to bus" (linger alone is not enough).

## `set -e` + a trailing `[ x = y ] && …` leaks a non-zero exit (autonomous bootstrap)

`bootstrap.sh` ended on `[ "${SA_PROFILE}" = "interactive" ] && log …`. Under `set -e`,
the script inherits that test's status as its own exit code. On the **autonomous** profile
the test is false → the `&&` short-circuits → the script exits **1**, even though every
install step succeeded. cloud-init then marks user-data failed (`cloud-init status` =
`error`, `scripts_user` WARNING) and the outer trap prints `BOOTSTRAP FAILED`. The
interactive profile masks it (test true → exit 0), which is why the dev-box never hit it.
Fix: end the script with an explicit `exit 0` (and prefer a real `if … fi` over a trailing
bare conditional). The sa#35 live capstone surfaced this; a unit test now asserts the last
statement is `exit 0`.

## netns + broker-proxy confinement: the two live unknowns resolved *positively* (sa#35)

The autonomous netns model (`agent-netns-setup.service` + `broker-model-proxy.service`,
the agent exec'd via `ip netns exec agent-ns runuser -w … -u dev`) was live-validated on a
real RHEL 9 box. Two behaviors the unit tests can't cover both worked with **no extra
configuration needed**:

- **SELinux allows `init_t` → `ip netns exec`.** The root oneshot system service creates the
  netns and veth with **zero AVC denials** (`ausearch -m avc` empty). No targeted policy
  allow is required — provided the exec'd scripts live under `/opt` (see the 203/EXEC note).
- **`runuser -w CLAUDE_CODE_OAUTH_TOKEN,HTTPS_PROXY,…` passes the env into the namespace.**
  The token (fetched in the root netns) and `HTTPS_PROXY` arrive inside `agent-ns` for the
  unprivileged `dev` user; a real `claude -p` returns an answer through the broker proxy. No
  need for the fallback 0600 env-file hand-off. `smoke-egress.sh` passes all four assertions
  (connector blocked, broker reachable, model blocked direct, model reachable via proxy).

## SSM send-command: base64-encode box-side scripts

Raw heredocs / multi-line commands in SSM `AWS-RunShellScript` JSON break on quotes, shell
metacharacters, and newlines (and `openshell sandbox exec` rejects newlines in command args
outright). Encode the script with `base64 | tr -d '\n'`, ship that, and `base64 -d | bash`
on the box. Use a JSON payload file (`--cli-input-json`) rather than the `--parameters`
shorthand to avoid CLI-level quoting failures.
