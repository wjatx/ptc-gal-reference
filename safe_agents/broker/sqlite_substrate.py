"""sqlite_substrate.py — the shared SQLite substrate for local durable stores (product-wrapper Phase 1).

The first durable local backend: one ``broker.db`` file, stdlib ``sqlite3`` (zero
new dependency), WAL mode so the gateway daemon and the ceremony CLI — separate
processes on one file — see each other's committed writes. Every future sqlite
store (MCP registry/proposals now; counters/intents/envelope/grants in the next
slice) builds on this module rather than growing its own connection handling.

**Item-shaped schema is a ruling, not a preference** (maintainer, 2026-07-24): rows are
``(pk, sk, item-JSON)`` plus indexed ``expires_at``/``period`` columns — the
same key layout as the DynamoDB single-table stores, so ``example-wrapper migrate`` stays a
row pump (sqlite row → Dynamo item, attribute map verbatim), never a schema
translation. The ``item`` column holds the NON-key attribute map; pk/sk live
only in their columns, so the two can never diverge.

Conditional-write semantics (#190) come from the transaction shape, not a
condition-expression DSL: every write runs inside ``BEGIN IMMEDIATE``, which
takes the single writer lock up front — a read-check-write sequence inside the
transaction is therefore serialized against every other writer, exactly the
atomicity a DynamoDB ConditionExpression provides. WAL readers never block on
the writer. There is no blind REPLACE anywhere: creates are plain INSERTs (a
duplicate key is an integrity error, mapped by the caller to its append-only
vocabulary) and updates are guarded UPDATEs on a row the same transaction just
evaluated.

Durability: ``synchronous=FULL`` under WAL — each commit is fsync'd. The
ceremony writes admissions and ledger records; write volume is human-paced and
the trust properties are worth the sync.

Expiry/period are PREDICATES AT USE (the sa#213 doctrine — deletion timing is
never correctness): the indexed columns exist so a later boot+timer sweep can
find candidates cheaply, but nothing in this module deletes.

**A store may be opened read-only, and that is a security seam** (#203): the
grant ceremony's maker half reads the grant store to assemble evidence but must
be structurally unable to write it, which on a cluster means the file arrives on
a read-only mount and the kernel issues the refusal. Supporting that costs this
module a second open path (no ``mkdir``, no pragma write, no schema bootstrap)
and a second journal mode, because a WAL database cannot be opened read-only at
all. See :data:`JOURNAL_DELETE` and :func:`_open_read_only`.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Iterator

# Schema version stamped into `meta` at bootstrap. Bump ONLY with an explicit,
# documented migration — a version this module does not recognize refuses
# loudly rather than guessing at the layout.
SCHEMA_VERSION = "1"

# The two journal modes this substrate supports, as a CLOSED set — a journal
# mode is selected by deployment topology, so it takes the same treatment as
# every other runtime-selectable name in this codebase: an enumerated choice,
# never a string handed through to sqlite.
#
# WAL is the default and stays the default: readers never block the writer,
# which is what a gateway daemon and a ceremony CLI sharing one file want.
#
# DELETE exists for exactly one reason (#203): **a WAL database cannot be
# opened from a read-only mount at all.** WAL keeps its index in a `-shm`
# sidecar that every reader must map read-write, so a reader on a read-only
# filesystem fails at OPEN with "attempt to write a readonly database" — a
# failure that looks like our bug rather than the intended refusal.
#
# The alternative, `immutable=1`, was measured and REJECTED: it makes the
# reader assert the file cannot change, and when that assertion is wrong the
# reader silently returns pre-WAL data. Measured on this substrate's shape, a
# checker committing a PROMOTION to `out-of-loop` left an `immutable=1` reader
# still seeing `in-loop` — a stale grant level, with no error to say so.
#
# Say nothing about which direction that stale value points. The measured run
# happens to go the lucky way (`in-loop` is the BOTTOM of the ladder — see
# grants/rung.py:20-30, where promotion ascends in-loop -> on-loop ->
# out-of-loop), but a reader pinned to pre-WAL contents returns whatever those
# contents were, so a demotion the checker had just committed would read back
# as the higher level it replaced. The defect is that the read is stale and
# SILENT; direction is a property of the run, not of the flag. A control whose
# read path rests on an unverifiable promise is not the control this phase is
# buying.
JOURNAL_WAL = "wal"
JOURNAL_DELETE = "delete"
_JOURNAL_MODES = (JOURNAL_WAL, JOURNAL_DELETE)

# How long a writer waits on the single write lock before sqlite gives up
# (SQLITE_BUSY). The ceremony CLI and a gateway daemon contend rarely and
# briefly; 5s is generous for human-paced writes without hanging a wedged CLI.
_BUSY_TIMEOUT_MS = 5000

_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS items (
        pk TEXT NOT NULL,
        sk TEXT NOT NULL,
        item TEXT NOT NULL,
        expires_at TEXT,
        period TEXT,
        PRIMARY KEY (pk, sk)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_items_expires_at
        ON items (expires_at) WHERE expires_at IS NOT NULL
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_items_period
        ON items (period) WHERE period IS NOT NULL
    """,
    """
    CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
)


class SqliteSchemaError(Exception):
    """The database file carries a schema version this code does not know.

    Refuse loudly instead of reading a layout we might misinterpret — a wrong
    guess about the item shape could serve tampered-looking (or worse,
    tampered-but-clean-looking) rows.
    """


class SqliteReadOnlyError(Exception):
    """A read-only open cannot proceed — the file is absent or unbootstrapped.

    Distinct from :class:`SqliteSchemaError` because the operator action is
    different: a schema error means migrate, this means the mount is wrong.
    """


def _checked_journal_mode(journal_mode: str) -> str:
    if journal_mode not in _JOURNAL_MODES:
        raise ValueError(
            f"journal_mode={journal_mode!r} is not in the closed set "
            f"{_JOURNAL_MODES!r}; a journal mode is deployment topology, not "
            "free text handed to sqlite"
        )
    return journal_mode


def _verify_schema(conn: sqlite3.Connection, path: Path) -> None:
    """The read-only twin of :func:`_ensure_schema` — SELECT, never CREATE.

    An unbootstrapped file is refused rather than treated as empty, for the
    same reason absence is: a store with no ``items`` table and a store with no
    grants are indistinguishable to a caller, and only one of them is a
    legitimate state to assemble evidence against.
    """
    try:
        row = conn.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'"
        ).fetchone()
    except sqlite3.OperationalError as exc:
        raise SqliteReadOnlyError(
            f"{str(path)!r} opened read-only but carries no schema ({exc}); a "
            "read-only open cannot bootstrap one. An unbootstrapped store is "
            "not an empty store — refusing rather than reading it as 'nothing "
            "is granted'."
        ) from exc
    if row is None or row[0] != SCHEMA_VERSION:
        found = "absent" if row is None else repr(row[0])
        raise SqliteSchemaError(
            f"{str(path)!r} has schema_version={found} but this code expects "
            f"{SCHEMA_VERSION!r}; refusing to read a layout it might "
            "misinterpret — run the documented migration for this version"
        )


def open_connection(
    db_path: str | Path,
    *,
    journal_mode: str = JOURNAL_WAL,
    read_only: bool = False,
) -> sqlite3.Connection:
    """Open ONE configured connection to the local store database.

    Creates parent directories for a named path (the operator named it; a
    missing directory is setup, not a policy question). The connection is in
    autocommit mode (``isolation_level=None``) — transactional writes go
    through :func:`transaction`, which issues an explicit ``BEGIN IMMEDIATE``.
    Schema bootstrap is idempotent and runs on every open, so a fresh file is
    usable immediately and an existing file is verified against
    ``SCHEMA_VERSION``.

    Connections are single-thread (sqlite3's default check) and each store
    instance holds its own; cross-process and cross-connection visibility is
    WAL's job, not shared handles.

    ``read_only`` opens the file with no write of any kind — see
    :func:`_open_read_only` for why that needs its own path rather than a
    ``query_only`` pragma, and ``journal_mode`` for why a read-only-mounted
    database must not be WAL.
    """
    if read_only:
        return _open_read_only(db_path)
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), isolation_level=None)
    conn.execute(f"PRAGMA journal_mode={_checked_journal_mode(journal_mode)}")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
    _ensure_schema(conn)
    return conn


def _open_read_only(db_path: str | Path) -> sqlite3.Connection:
    """Open a database the process must not — and CANNOT — write (#203).

    This exists so the maker half of the ceremony can read the grant store it
    is structurally forbidden to write: on OpenShift the grant database arrives
    on a ``readOnly: true`` mount, so the refusal is the kernel's rather than a
    check of ours. A caller that merely *intends* not to write would use
    ``PRAGMA query_only``; that is an honour-system flag inside our own process
    and buys nothing against a compromised agent, which is the whole point.

    Every write the normal open performs has to go, not just the INSERTs:
    ``mkdir`` on the parent, the ``journal_mode`` pragma, and the
    ``CREATE TABLE IF NOT EXISTS`` bootstrap all fail on a read-only mount. So
    the schema version is VERIFIED by SELECT here rather than ensured, and an
    absent file REFUSES rather than being created — the #205 reasoning applies
    unchanged: a silently-fresh empty database reads as "no grants exist",
    which fails toward *more* authority for a maker assembling evidence.
    """
    path = Path(db_path)
    if not path.exists():
        raise SqliteReadOnlyError(
            f"refusing to open {str(path)!r} read-only: the file does not exist. "
            "A read-only open cannot create it, and treating absence as an empty "
            "store would read as 'no grants exist' — evidence assembled against a "
            "phantom store, failing toward more authority. Check the mount."
        )
    # as_uri() rather than f"file:{path}": it percent-encodes the path, so a '?',
    # '#' or '%' in a directory name cannot be read as URI syntax, and on Windows
    # it yields the file:///C:/... form SQLite expects instead of a bare drive path
    # full of backslashes.
    uri = path.absolute().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, isolation_level=None)
    conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
    _verify_schema(conn, path)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    with transaction(conn):
        for statement in _SCHEMA_STATEMENTS:
            conn.execute(statement)
        row = conn.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'"
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
                (SCHEMA_VERSION,),
            )
        elif row[0] != SCHEMA_VERSION:
            raise SqliteSchemaError(
                f"database schema_version={row[0]!r} but this code expects "
                f"{SCHEMA_VERSION!r}; refusing to read a layout it might "
                "misinterpret — run the documented migration for this version"
            )


class SqliteStoreBase:
    """Shared connection lifecycle for every sqlite store — one lazily-opened
    connection per store instance, on the db path the CALLER resolved.

    Homed here rather than per-package because this module's contract is
    "every future sqlite store builds on this rather than growing its own
    connection handling": by the grants slice the same six lines had been
    copied into five stores, so the copies were the demand signal. Subclasses
    add only their own state (an HMAC key, say) and call ``super().__init__``.

    The db path arrives as a constructor argument, never from the environment:
    ``boot_config.resolve_sqlite_db_path`` is the ONE env-var seam for it, so
    no store module reads ``BROKER_SQLITE_PATH`` itself.

    Lazy is load-bearing, not an optimization: constructing a store touches no
    disk, so a boot that REFUSES before first use (the #205 named-config-or-
    refuse seams) leaves no database file behind at all.

    ``journal_mode`` and ``read_only`` are per-store because the #203 split
    puts the checker-writable key space (``GRANT#``/``RECORD#``/``TOOLDEF#``/
    ``TOOLREC#``) in its own database file, which the maker mounts read-only.
    Both default to today's behaviour exactly, so a deployment that does not
    split is byte-for-byte unchanged.
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        journal_mode: str = JOURNAL_WAL,
        read_only: bool = False,
    ) -> None:
        self._db_path = Path(db_path)
        self._journal_mode = _checked_journal_mode(journal_mode)
        self._read_only = read_only
        self._conn: sqlite3.Connection | None = None

    def _connection(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = open_connection(
                self._db_path,
                journal_mode=self._journal_mode,
                read_only=self._read_only,
            )
        return self._conn

    def close(self) -> None:
        """Close the underlying connection (idempotent). A later call reopens."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None


@contextlib.contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """One write transaction: BEGIN IMMEDIATE → body → COMMIT; any raise → ROLLBACK.

    IMMEDIATE takes the writer lock at BEGIN, so reads inside the body see a
    state no other writer can change before COMMIT — the substrate's whole
    conditional-write guarantee. Nothing is written unless the body completes.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def get_item(conn: sqlite3.Connection, pk: str, sk: str) -> dict | None:
    """The non-key attribute map at (pk, sk), or None."""
    row = conn.execute(
        "SELECT item FROM items WHERE pk = ? AND sk = ?", (pk, sk)
    ).fetchone()
    if row is None:
        return None
    return json.loads(row[0])


def get_partition(conn: sqlite3.Connection, pk: str) -> list[tuple[str, dict]]:
    """Every (sk, attribute-map) under one pk, ordered by sk ascending —
    the sqlite mirror of a DynamoDB Query with ScanIndexForward=True."""
    rows = conn.execute(
        "SELECT sk, item FROM items WHERE pk = ? ORDER BY sk ASC", (pk,)
    ).fetchall()
    return [(sk, json.loads(item)) for sk, item in rows]


def put_new_item(
    conn: sqlite3.Connection,
    pk: str,
    sk: str,
    attrs: dict,
    *,
    expires_at: str | None = None,
    period: str | None = None,
) -> None:
    """Create-only write: a plain INSERT, never REPLACE (#190).

    Raises ``sqlite3.IntegrityError`` if (pk, sk) exists — the caller maps
    that to its own append-only / already-exists vocabulary. Inside a
    :func:`transaction` whose body already checked absence, the error is
    unreachable; the INSERT stays guarded anyway so a caller that skips the
    check still cannot overwrite.
    """
    conn.execute(
        "INSERT INTO items (pk, sk, item, expires_at, period) VALUES (?, ?, ?, ?, ?)",
        (pk, sk, _dump_attrs(attrs), expires_at, period),
    )


def update_existing_item(
    conn: sqlite3.Connection,
    pk: str,
    sk: str,
    attrs: dict,
    *,
    expires_at: str | None = None,
    period: str | None = None,
) -> None:
    """Overwrite an item the SAME transaction already read and condition-checked.

    Guarded: refuses (LookupError) if the row is absent — an update landing on
    nothing means the caller's read and write disagree, which inside BEGIN
    IMMEDIATE indicates a caller bug, never a race.
    """
    cursor = conn.execute(
        "UPDATE items SET item = ?, expires_at = ?, period = ? WHERE pk = ? AND sk = ?",
        (_dump_attrs(attrs), expires_at, period, pk, sk),
    )
    if cursor.rowcount != 1:
        raise LookupError(
            f"update_existing_item({pk!r}, {sk!r}) matched {cursor.rowcount} rows; "
            "the caller must read-and-check inside the same transaction"
        )


def _dump_attrs(attrs: dict) -> str:
    return json.dumps(attrs, sort_keys=True, ensure_ascii=True)
