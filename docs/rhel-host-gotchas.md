# RHEL/EL host gotchas (agent arms)

Battle scars from standing up RHEL-family hosts (first hit while building a development-harness box;
captured here so we don't rediscover them when building the EC2/Fargate agent arms). These two bite
*any* RHEL/Amazon-Linux host, independent of OpenShell — so they're in scope for the autonomous arms
even though OpenShell is dev-box-only.

## 1. SELinux: a systemd *system* service can't exec a script under `/home` (`203/EXEC`)

**Symptom.** A systemd service fails to start with exit status **`203/EXEC`**; the journal shows it
could not execute its `ExecStart` script.

**Root cause.** Under SELinux, a *system* service runs in the `init_t` domain, and files under
`/home` are labeled `user_home_t`. SELinux **denies `init_t` from executing `user_home_t`** — so the
unit can't run a script that lives in a user's home directory.

**Fixes (in preference order):**
1. **Put platform executables outside `/home`** — `/opt/<thing>/` or `/usr/local/bin` (labeled
   types `init_t` may exec). This is the right default for the broker process, runner wrappers,
   boot emitters, and timers on an agent host.
2. **Run it as a systemd *user* service** instead of a system service — the user's systemd manager
   is unconfined and *can* exec from `/home`. (This is what the development harness does for its
   remote-control and resource-watch services.) Pair with `loginctl enable-linger <user>` so it starts at boot without a login.
3. Relabeling with `chcon`/`semanage` is possible but fragile (a restorecon wipes `chcon`); avoid.

**Relevance to the arms.** Every systemd unit we add on an agent host is subject to this. Default to
installing platform binaries under `/opt` or `/usr/local/bin`; reach for user services only when the
thing genuinely needs the user session.

## 2. `/usr/local/bin` is not on the service-user PATH (`aws: command not found`)

**Symptom.** A script run as a non-root service user (or non-interactively over SSM) fails with
`aws: command not found` — even though `aws` is installed and on root's PATH.

**Root cause.** The RHEL user login shell's `PATH` can **omit `/usr/local/bin`**, which is where the
AWS CLI v2 installs (`/usr/local/bin/aws`). If a script calls `aws` *before* it sets `PATH`, the call
fails; root works only because root's PATH includes it.

**Fix.** **Export `PATH` first**, before any `aws`/CLI call, including `/usr/local/bin` (and any
project venv):

```sh
export PATH="/opt/<app>/venv/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
# ...only now call aws / jq / etc.
```

**Relevance to the arms.** Any provisioning or wrapper script that runs as a service user and shells
out to `aws` (broker bootstrap, runner wrappers, smoke checks) must be PATH-first. Don't trust the
inherited PATH for non-interactive service-user execution.
