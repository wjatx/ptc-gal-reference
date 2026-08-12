"""broker.envelope — the in-force risk Envelope's store, seed, and read seam.

Phase 3 Slice A of the broker-destub epic (sa#136): DynamoDB (seeded from the
authored agents/*.yaml `envelope:` block) becomes the broker's source for its
in-force Envelope. Config-as-code (the yaml) stays the authorship source; the
seed step here canonicalizes it into the store; `load_inforce_envelope` is the
read seam Slice B wires into build_runtime. Nothing in this package is
consumed by the running broker yet.

Three surfaces:

  store  — EnvelopeStore Protocol + InMemoryEnvelopeStore (tests) +
           DynamoDBEnvelopeStore (production, co-located in the grants table
           as a distinct "ENVELOPE#" item type — see store.py's docstring for
           why no new CDK/IAM is needed).

  seed   — seed_envelope(): reads an agents/<name>.yaml's `envelope:` block,
           validates it as an Envelope, and writes it to the store. Mirrors
           grants/prototype/seed_grants.py's out-of-band seeding pattern.

  read   — load_inforce_envelope(): the source-agnostic read seam. Slice B
           wires this into build_runtime; do not call it from anywhere else
           yet.

See broker/schemas/envelope.py for the Envelope type and compute_envelope_hash.
"""

from .read import EnvelopeNotFoundError, load_inforce_envelope
from .seed import EnvelopeSeedError, load_envelope_block, seed_envelope
from .store import DynamoDBEnvelopeStore, EnvelopeStore, InMemoryEnvelopeStore

__all__ = [
    # store
    "EnvelopeStore",
    "InMemoryEnvelopeStore",
    "DynamoDBEnvelopeStore",
    # seed
    "EnvelopeSeedError",
    "load_envelope_block",
    "seed_envelope",
    # read
    "EnvelopeNotFoundError",
    "load_inforce_envelope",
]
