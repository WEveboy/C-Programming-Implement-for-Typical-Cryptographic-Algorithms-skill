"""Execute bounded data-path models of book pp.206/216, not complete hashes.

The frozen synthetic inputs and expected defect decisions are declared before
execution. Compression calls are captured verbatim; F8/BLAKE are not supplied.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLAN = {
    "blake": [
        {"id": "b-1-63", "chunks": ["a5", bytes(range(63)).hex()], "source_defect": False},
        {"id": "b-1-64", "chunks": ["a5", bytes(range(64)).hex()], "source_defect": True},
        {"id": "b-63-1", "chunks": [bytes(range(63)).hex(), "a5"], "source_defect": False},
        {"id": "b-1-empty", "chunks": ["a5", ""], "source_defect": True},
        {"id": "b-empty-64", "chunks": ["", bytes(range(64)).hex()], "source_defect": False},
        {"id": "b-2-128", "chunks": ["a5b6", bytes(range(128)).hex()], "source_defect": True},
        {"id": "b-63-65", "chunks": [bytes(range(63)).hex(), bytes(range(65)).hex()], "source_defect": False},
        {"id": "b-64-1", "chunks": [bytes(range(64)).hex(), "a5"], "source_defect": False},
    ],
    "jh": [
        {"id": f"j-{n}-{bit}", "bits": bit * n, "source_defect": bit == "1"}
        for n in range(1, 8) for bit in ["0", "1"]
    ] + [
        {"id": f"j-boundary-{n}", "bits": "1" * n, "source_defect": bool(n % 8)}
        for n in [0, 8, 9, 15, 511, 512]
    ],
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def blake_fragment(chunks, revised):
    """Model byte-aligned p.206 Update, including the printed buffer guard."""
    pending = b""
    blocks = []
    for chunk in chunks:
        if revised and not chunk:
            continue
        left = len(pending)
        fill = 64 - left
        available = len(chunk) if revised else len(chunk) & 0x3F
        if left and available >= fill:
            blocks.append(pending + chunk[:fill])
            chunk = chunk[fill:]
            pending = b""
            left = 0
        while len(chunk) >= 64:
            blocks.append(chunk[:64])
            chunk = chunk[64:]
        if chunk:
            pending = pending[:left] + chunk
        else:
            # p.206: else S->buflen=0, even when an old tail exists.
            pending = b""
    return {"blocks": [b.hex() for b in blocks], "pending": pending.hex()}


def expected_stream(chunks):
    stream = b"".join(chunks)
    full = len(stream) // 64 * 64
    return {"blocks": [stream[i:i + 64].hex() for i in range(0, full, 64)],
            "pending": stream[full:].hex()}


def jh_fragment(bits, revised):
    """Capture only first padding block, before p.216 F8; no hash execution."""
    tail = bits[len(bits) // 512 * 512:]
    block = bytearray(64)
    for i, bit in enumerate(tail):
        if bit == "1":
            block[i // 8] |= 1 << (7 - i % 8)
    if not tail:
        block[0] = 0x80
    else:
        index = len(tail) // 8
        padding = 1 << (7 - len(tail) % 8)
        if revised:
            valid = len(tail) % 8
            mask = (0xFF << (8 - valid)) & 0xFF if valid else 0
            block[index] = (block[index] & mask) | padding
        else:
            block[index] = padding
    return block.hex()


def expected_jh_prefix(bits):
    tail = bits[len(bits) // 512 * 512:]
    # Independent bit-string packing rather than the fragment's byte writes.
    padded = (tail + "1").ljust(512, "0")
    return int(padded, 2).to_bytes(64, "big").hex()


def main():
    rows = []
    for case in PLAN["blake"]:
        chunks = [bytes.fromhex(x) for x in case["chunks"]]
        expected = expected_stream(chunks)
        source = blake_fragment(chunks, False)
        revised = blake_fragment(chunks, True)
        rows.append({"id": case["id"], "family": "blake-update-fragment",
                     "source_matches_invariant": source == expected,
                     "expected_source_defect": case["source_defect"],
                     "revised_matches_invariant": revised == expected,
                     "source": source, "revised": revised, "expected": expected,
                     "passed": (source != expected) == case["source_defect"] and revised == expected})
    for case in PLAN["jh"]:
        expected = expected_jh_prefix(case["bits"])
        source = jh_fragment(case["bits"], False)
        revised = jh_fragment(case["bits"], True)
        rows.append({"id": case["id"], "family": "jh-padding-fragment",
                     "source_matches_invariant": source == expected,
                     "expected_source_defect": case["source_defect"],
                     "revised_matches_invariant": revised == expected,
                     "source": source, "revised": revised, "expected": expected,
                     "passed": (source != expected) == case["source_defect"] and revised == expected})
    # Equal-length 0/1 payloads must not collapse merely while adding padding.
    collisions = [{"bits": n,
                   "source_collides": jh_fragment("0" * n, False) == jh_fragment("1" * n, False),
                   "revised_distinct": jh_fragment("0" * n, True) != jh_fragment("1" * n, True)}
                  for n in range(1, 8)]
    report = {
        "schema_version": 1,
        "execution_mode": "actual_execution_of_python_fragment_models",
        "scope": "Book p.206 BLAKE Update byte-buffer path and p.216 JH first padding block; no compression/hash output or original C execution",
        "input_plan": PLAN,
        "input_plan_sha256": digest(json.dumps(PLAN, sort_keys=True, separators=(",", ":")).encode()),
        "script_sha256": digest(Path(__file__).read_bytes()),
        "planned": len(rows), "completed": len(rows),
        "passed": sum(r["passed"] for r in rows),
        "source_defects_demonstrated": sum(not r["source_matches_invariant"] for r in rows),
        "results": rows, "jh_collision_checks": collisions,
        "limitations": ["Source/revised data-path models are independently compared to byte-stream/bit-string invariants, not full BLAKE/JH KATs.",
                        "No claim of production readiness, complete source recovery, or hash cryptanalysis.",
                        "The JH model does not execute F8, the second length block, or streaming Update."]}
    out = ROOT / "evaluation/reports/hash-source-defects.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({k: report[k] for k in ["planned", "completed", "passed", "source_defects_demonstrated"]}))
    if report["passed"] != len(rows) or not all(c["source_collides"] and c["revised_distinct"] for c in collisions):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
