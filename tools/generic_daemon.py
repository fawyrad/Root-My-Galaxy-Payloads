#!/usr/bin/env python3
"""Which KMIs a daemon carries, and the feed entry that offers it.

A pair's daemon embeds exactly the module built for its own target, so it is served to that one
device. That is the right default. The KernelSU half is also the only part of a payload that does
not have to be device-specific: `ksud` picks its kernel module from its own asset directory by KMI
at run time - `format!("{kmi}_kernelsu.ko")` - so a daemon carrying one module per KMI serves every
device whose KMI is in that set. The hand-built `ksud-samsung-*` bundles already work this way
(`ksud-samsung-android12-5.10-kdp` carries three KMIs), and this is the tool that reads that set
back out of a binary instead of trusting a name that only mentions one of them.

Two things are read, and neither is guessed at:

- **The asset table.** The loader indexes it by KMI, and it is a contiguous run of
  `<kmi>_kernelsu.ko` names in rodata. It is the only evidence that a daemon carries a module
  rather than having been built beside one - which is why the size of a daemon is not a proxy for
  it, and why a name like `ksud-samsung-android12-5.10-kdp` cannot be parsed for the set.
- **The version** the daemon was stamped with, from `pairs.daemon_version`, which is `ksud -V`'s own
  answer (`3.3.0 (uapi: 4)`). A generic daemon is rebuilt when a KernelSU release moves, so this is
  what a client needs to offer the manager that matches the kernel the run loads.

The feed this writes is a separate file, `support/kernelsu-generic.json`, and that is deliberate:
`support/targets-v3.json` is a released client contract that is rewritten in place by span edits,
and a device's entry in it has to keep naming exactly the artifact that device was tested with. A
generic daemon is a tier of its own, so it gets a file of its own, and the entries that are working
today are not touched by any of this.

The version is the one thing a generic daemon cannot always be asked for. The three hand-built
bundles already in this repository - `ksud-s25u-kdp` and its two siblings - predate the version
string `ksud -V` answers with, and read back as nothing at all; the self-test below pins that,
because it is the reason `--version` comes from the run's tag rather than from the binary. A daemon
built by the workflow below is stamped, so the two agree - but a publish that *needed* the binary
to answer would silently drop the field on an entry the app needs it for.

There is a third answer, and it is neither of those: a daemon built from a *branch* has no release to
name. `--branch` says so, and the entry it writes declares no version at all - the state the app
already reads as "nothing declared, offer the flavour's own release", and the only honest one for a
build whose `git describe` ends in `-g<commit>`. Without it a rebuild of the test line writes that
line's own name into a field that exists to name a release, and the manager the app then offers is
looked up under a version no project publishes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import textwrap

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pairs import FLAVOURS, daemon_version  # noqa: E402

# `<kmi>_kernelsu.ko`, which is the name the loader builds for itself.
#
# Anchored on the name alone rather than on a path, because the asset table is a run of bare names.
# The pattern deliberately cannot match the neighbours that sit in the same table - `busybox`,
# `bootctl`, and `reboot_kernelsu.ko`, which has the `_kernelsu.ko` ending and no `-<major>.<minor>`
# before it - so the set read back is the module set and not everything in the directory.
ASSET = re.compile(rb"(?P<kmi>android\d+-\d+\.\d+(?:\.\d+)?)_kernelsu\.ko")

# The file the generic tier is served from. One name, imported by nothing else, so a run that writes
# it cannot be confused with a run that edits the released feed.
GENERIC_FEED = "support/kernelsu-generic.json"

# The KMIs each checked-in daemon carries, and the version it answers with, which is what the
# self-test holds the reader to. Both are read off the artifacts rather than from
# `kernelsu/README.md`, which describes the 5.10 bundle as embedding "the 5.10 module" while the
# binary carries three.
#
# `None` is a fact and not a gap in the fixture: the three hand-built bundles were built before the
# version string existed, so they answer with nothing. That is what makes the workflow pass
# `--version` from its tag instead of reading the entry's version out of the artifact, and a rebuilt
# generic daemon is expected to fill this in.
SELF_TEST = {
    "ksud-samsung-android12-5.10-kdp": (["android12-5.10", "android14-6.1", "android15-6.6"], None),
    "ksud-samsung-android14-6.1-kdp": (["android14-6.1", "android15-6.6"], None),
    "ksud-s25u-kdp": (["android15-6.6"], None),
    "ksud-next-pa3q-S938USQSCCZF9-kdp": (["android15-6.6"], "3.4.0"),
    "ksud-rsksu-pa3q-S938USQSCCZF9-kdp": (["android15-6.6"], "4.2.0-rc3"),
}


def carried(path: str) -> list[str]:
    """The KMIs a daemon's asset table offers, sorted. Empty when it carries no module of its own."""
    with open(path, "rb") as handle:
        data = handle.read()
    return sorted({match.group("kmi").decode() for match in ASSET.finditer(data)})


def _digest(path: str) -> tuple[int, str]:
    size = os.path.getsize(path)
    hash_ = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            hash_.update(block)
    return size, hash_.hexdigest()


def _as_list(text: str) -> list[str]:
    """A KMI set given either as JSON or as a comma-separated list, in the order written."""
    text = text.strip()
    if not text:
        return []
    if text.startswith("["):
        parsed = json.loads(text)
        if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
            raise SystemExit(f"not a KMI array: {text}")
        return parsed
    return [part.strip() for part in text.split(",") if part.strip()]


def verify(path: str, daemon: str, expect: list[str]) -> list[str]:
    """The KMI set, having checked it is the set the run built. Refuses rather than reports."""
    if not os.path.isfile(path):
        raise SystemExit(f"no daemon at {path}")

    kmis = carried(path)
    if not kmis:
        raise SystemExit(
            f"{daemon} carries no <kmi>_kernelsu.ko asset, so it cannot serve any device as a "
            "generic daemon. A daemon built with no module staged beside it has nothing to load."
        )
    if sorted(expect) != kmis:
        raise SystemExit(
            f"{daemon} carries {kmis}, but this run built {sorted(expect)}. The two are the same "
            "list or the entry would offer a device a KMI the daemon has no module for."
        )
    return kmis


def entry_for(
    repo: str,
    daemon: str,
    artifact: str,
    flavour: str,
    expect: list[str],
    url_prefix: str | None,
    version: str | None,
    branch: bool = False,
) -> dict:
    """The feed entry for one daemon, built from what the artifact itself says.

    Everything here is read rather than passed in where it can be, for the reason the pair jobs do
    the same: the KMI set is the daemon's own asset table, the version is the one it was stamped
    with, and the size and digest are of the file being published. A caller that disagrees with the
    binary is refused instead of overwriting the difference.
    """
    path = os.path.join(repo, artifact)
    kmis = verify(path, daemon, expect)

    # The tag the run built at first, the binary second, and normalised to the form the feed's
    # `version` field carries - `v3.4.0` and `3.4.0` are the same release and only the second is what
    # the app compares a manager's own version against. The pair publish reads the ref the same way
    # and for the same reason: a hand-built or older daemon often carries nothing readable, and an
    # entry that declares no version leaves the app falling back to the flavour's own release for the
    # manager it offers - which is only correct while the two happen to be the same number.
    #
    # A branch is the third answer and it is not a version, so it bypasses both readings rather than
    # filling the field with a name no release answers to.
    stamped: str | None = None if branch else (version or daemon_version(path) or "").lstrip("vV")
    if not branch and not stamped:
        raise SystemExit(
            f"{daemon} carries no readable version and none was given. A generic daemon is offered to "
            "devices that have no target entry of their own, so the manager the app installs cannot "
            "fall back to an entry's own release - the daemon or the run has to say what it was built "
            "from. Pass --version $(the run's tag)."
        )

    # A URL is never invented from scratch where one already exists: an entry that is already served
    # keeps its own prefix, which is what satisfies the client's allowed-repository rule.
    previous = _existing(repo, flavour)
    if url_prefix is None and previous is not None:
        url_prefix = previous["daemon"]["url"].rsplit("/", 1)[0]
    if url_prefix is None:
        raise SystemExit(
            "no --url-prefix and no entry to take one from. The first publish of a flavour has to "
            "name the repository its artifacts are served from."
        )

    size, sha256 = _digest(path)
    served = {
        "url": f"{url_prefix.rstrip('/')}/kernelsu/{daemon}",
        "size": size,
        "sha256": sha256,
    }
    # Absent rather than null, which is the shape the feed carries for this already: a null would be a
    # value the app has to special-case, and there is nothing to say.
    if stamped:
        served["version"] = stamped
    return {"flavor": flavour, "kmis": kmis, "daemon": served}


def _read_feed(repo: str) -> dict:
    path = os.path.join(repo, GENERIC_FEED)
    if not os.path.isfile(path):
        return {"schemaVersion": 1, "generic": []}
    with open(path, encoding="utf-8") as handle:
        manifest = json.load(handle)
    manifest.setdefault("schemaVersion", 1)
    manifest.setdefault("generic", [])
    return manifest


def _existing(repo: str, flavour: str) -> dict | None:
    for entry in _read_feed(repo)["generic"]:
        if entry.get("flavor") == flavour:
            return entry
    return None


def _render(entry: dict) -> str:
    """One entry, indented to sit in the `generic` array.

    Serialised per entry rather than for the whole file, because an entry's own text is all a publish
    is allowed to touch - see `publish`.
    """
    return textwrap.indent(json.dumps(entry, indent=2, ensure_ascii=False), "    ")


def _scan(text: str, start: int, stop: int | None, on_object) -> None:
    """Walk JSON text, calling `on_object(start, end, body)` for each `{}` at depth 0.

    Hand-written rather than done with a span library because what this file needs is the *offset* of
    an object in the untouched text: the answer is used to splice, not to parse. String contents are
    skipped, so a brace or a bracket inside a URL cannot move a span.
    """
    depth = 0
    opened_at = None
    in_string = False
    i = start
    limit = len(text) if stop is None else stop
    while i < limit:
        char = text[i]
        if in_string:
            if char == "\\":
                i += 2
                continue
            if char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                opened_at = i
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0 and opened_at is not None:
                on_object(opened_at, i + 1, text[opened_at : i + 1])
        i += 1


def _generic_array(text: str) -> tuple[int, int]:
    """The `[` and the `]` of the top-level `generic` array."""
    key = text.find('"generic"')
    opened = text.find("[", key) if key >= 0 else -1
    if opened < 0:
        raise SystemExit(f"{GENERIC_FEED} has no `generic` array")
    # From the opening bracket to the one that closes it: depth returns to zero there.
    found: list[int] = []
    depth = 0
    in_string = False
    i = opened
    while i < len(text):
        char = text[i]
        if in_string:
            if char == "\\":
                i += 2
                continue
            if char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
        elif char in "}]":
            depth -= 1
            if depth == 0:
                found.append(i)
                break
        i += 1
    if not found:
        raise SystemExit(f"{GENERIC_FEED} has an unclosed `generic` array")
    return opened, found[0]


def _entry_spans(text: str) -> list[tuple[int, int, str]]:
    """`(start, end, flavour)` for every object in the `generic` array, in file order."""
    opened, closed = _generic_array(text)
    spans: list[tuple[int, int, str]] = []

    def record(start: int, end: int, body: str) -> None:
        found = re.search(r'"flavor"\s*:\s*"([^"]+)"', body)
        spans.append((start, end, found.group(1) if found else ""))

    _scan(text, opened + 1, closed, record)
    return spans


def publish(repo: str, entry: dict, dry_run: bool) -> str:
    """Write this flavour's entry, and *only* its own text. Returns what changed.

    Surgical on purpose. Each flavour is published by its own run, those runs can overlap, and the
    second commit is rebased onto the first - so a writer that reserialised the whole file would make
    every pair of publishes a conflict no rebase could resolve. Which is not hypothetical: the first
    run of this workflow published kernelsu and then failed to rebase resukisu onto it, with
    `could not apply`. Editing one entry's span leaves the rest of the file byte-identical, so the two
    commits touch different lines and rebase cleanly. `tools/update_feed.py` edits the released feed
    the same way, for the same reason.
    """
    path = os.path.join(repo, GENERIC_FEED)
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    else:
        text = '{\n  "schemaVersion": 1,\n  "generic": []\n}\n'

    indented = _render(entry)
    # The span starts at the object's `{`, so the indentation in front of it belongs to the file and is
    # not part of what is compared or written. Serialising it into the replacement instead would add a
    # level of indent to the entry on every republish, and comparing it would make an identical entry
    # look changed - which is a rewrite, a diff, and the rebase conflict this whole function avoids.
    body = indented.lstrip()

    for start, end, flavour in _entry_spans(text):
        if flavour != entry["flavor"]:
            continue
        if text[start:end] == body:
            return "unchanged"
        text = text[:start] + body + text[end:]
        action = "republished"
        break
    else:
        opened, closed = _generic_array(text)
        tail = text[closed:]
        if text[opened + 1 : closed].strip():
            # A comma only because something is already there, and the new entry goes last: an entry
            # that is replaced keeps its position, so a republish never reorders the file.
            text = f"{text[:closed].rstrip()},\n{indented}\n  {tail}"
        else:
            text = f"{text[:opened]}[\n{indented}\n  {tail}"
        action = "added"

    if not dry_run:
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    return action


def _self_test_publish() -> tuple[int, int]:
    """The writer, against two flavours in one file.

    They are published by two runs that can overlap, and the second commit is rebased onto the first,
    so an entry's own text has to be the only thing a publish touches - otherwise every pair of
    publishes conflicts. The workflow's first run did exactly that: kernelsu published, and resukisu
    then failed with `could not apply ... publish the generic resukisu daemon`.
    """
    import shutil  # noqa: PLC0415 - only the self-test needs these
    import tempfile

    failures = 0
    checks = 0

    def entry(flavour: str, kmis: list[str], version: str) -> dict:
        return {
            "flavor": flavour,
            "kmis": kmis,
            "daemon": {
                "url": f"https://example.test/main/kernelsu/ksud-{flavour}-generic-kdp",
                "size": 1,
                "sha256": "0" * 64,
                "version": version,
            },
        }

    def read(tmp: str) -> str:
        with open(os.path.join(tmp, GENERIC_FEED), encoding="utf-8") as handle:
            return handle.read()

    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "support"), exist_ok=True)
        first = entry("kernelsu", ["android15-6.6"], "3.3.0")
        second = entry("resukisu", ["android14-6.1"], "4.2.0-rc3")

        checks += 1
        if publish(tmp, first, False) != "added":
            print("FAIL the first publish into an empty feed is not an add")
            failures += 1

        checks += 1
        try:
            flavours = [item["flavor"] for item in json.loads(read(tmp))["generic"]]
        except json.JSONDecodeError as error:
            flavours = [f"<invalid JSON: {error}>"]
        if flavours != ["kernelsu"]:
            print(f"FAIL the feed after one publish reads {flavours}")
            failures += 1

        checks += 1
        if publish(tmp, second, False) != "added":
            print("FAIL a second flavour is not added alongside the first")
            failures += 1

        checks += 1
        text = read(tmp)
        try:
            flavours = [item["flavor"] for item in json.loads(text)["generic"]]
        except json.JSONDecodeError as error:
            flavours = [f"<invalid JSON: {error}>"]
        if flavours != ["kernelsu", "resukisu"]:
            print(f"FAIL two flavours in one feed read {flavours}")
            failures += 1

        # The point of the exercise: the first entry's own text is still byte for byte what it was, so
        # a rebase onto this commit has nothing to reconcile but the lines it added.
        checks += 1
        if _render(first) not in text:
            print("FAIL publishing the second flavour rewrote the first entry")
            failures += 1

        checks += 1
        if publish(tmp, entry("resukisu", ["android14-6.1"], "4.2.0-rc3"), False) != "unchanged":
            print("FAIL republishing an identical entry is not reported as unchanged")
            failures += 1

        changed = entry("resukisu", ["android14-6.1", "android15-6.6"], "4.2.0-rc3")
        checks += 1
        if publish(tmp, changed, False) != "republished":
            print("FAIL changing an entry in place is not reported as a republish")
            failures += 1

        checks += 1
        text = read(tmp)
        restored = json.loads(text)["generic"]
        if _render(first) not in text or restored[1] != changed or restored[0] != first:
            print("FAIL republishing one entry disturbed the one beside it")
            failures += 1

        # And it did not gain a level of indent either: the object's line carries the file's indent,
        # which is not part of the text being replaced.
        checks += 1
        if '\n        "flavor"' in text or text.count('\n    {') != 2:
            print(f"FAIL a republish moved the file's indentation: {text!r}")
            failures += 1

    return failures, checks


def self_test(repo: str = ".") -> int:
    """The reader, against the artifacts this checkout already carries."""
    failures = 0
    checks = 0
    artifacts = os.path.join(repo, "kernelsu")
    for daemon, (expected, expected_version) in SELF_TEST.items():
        path = os.path.join(artifacts, daemon)
        if not os.path.isfile(path):
            print(f"FAIL {daemon}: not in this checkout")
            failures += 1
            checks += 2
            continue

        checks += 1
        found = carried(path)
        if found == expected:
            print(f"ok   {daemon}: carries {', '.join(found)}")
        else:
            print(f"FAIL {daemon}: carries {found}, self-test says {expected}")
            failures += 1

        # Also the thing the feed needs and cannot invent. A daemon that answers with nothing is
        # publishable only because the run names the version; one that answers with something else is
        # a rebuild the entry would be pointing at the wrong manager for.
        checks += 1
        stamped = daemon_version(path)
        if stamped == expected_version:
            print(f"ok   {daemon}: version {stamped or '<none>'}")
        else:
            print(f"FAIL {daemon}: version {stamped or '<none>'}, self-test says {expected_version or '<none>'}")
            failures += 1

    # The names that share the asset table with the modules are not KMIs, and reading one as a KMI
    # would put a module in the entry that no device has.
    for name in (b"reboot_kernelsu.ko", b"busybox", b"bootctl"):
        checks += 1
        if ASSET.search(name):
            print(f"FAIL the asset pattern matches {name.decode()}")
            failures += 1

    publish_failures, publish_checks = _self_test_publish()
    failures += publish_failures
    checks += publish_checks

    if failures:
        print(f"self-test: {failures} of {checks} check(s) failed")
        return 1
    print(f"self-test: {len(SELF_TEST)} daemon(s), {checks} check(s), no non-module name matched")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true", help="read the checked-in daemons and stop")
    parser.add_argument(
        "--check",
        action="store_true",
        help="only check that a built daemon carries the set this run built, and write no feed",
    )
    parser.add_argument("--repo", default=".", help="payload repository root")
    parser.add_argument("--daemon", help="file name the daemon is published under")
    parser.add_argument("--artifact", help="path to the built daemon")
    parser.add_argument(
        "--flavor",
        default="kernelsu",
        choices=sorted(FLAVOURS.values()),
        help="which project's KernelSU the daemon is",
    )
    parser.add_argument("--expect", default="", help="the KMI set the run built, as JSON or as a list")
    parser.add_argument("--version", help="the KernelSU ref or release, e.g. v3.4.0; taken from the binary when absent")
    parser.add_argument(
        "--branch",
        action="store_true",
        help="the ref names a branch rather than a release, so the entry declares no version",
    )
    parser.add_argument("--url-prefix", help="repository raw-URL prefix this run publishes under")
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()

    if arguments.self_test:
        return self_test(arguments.repo)
    if not arguments.daemon or not arguments.artifact:
        parser.error("give --daemon and --artifact, or --self-test")

    if arguments.check:
        kmis = verify(os.path.join(arguments.repo, arguments.artifact), arguments.daemon, _as_list(arguments.expect))
        print(f"ok   {arguments.daemon}: carries {', '.join(kmis)}")
        return 0

    entry = entry_for(
        arguments.repo,
        arguments.daemon,
        arguments.artifact,
        arguments.flavor,
        _as_list(arguments.expect),
        arguments.url_prefix,
        arguments.version,
        arguments.branch,
    )
    action = publish(arguments.repo, entry, arguments.dry_run)
    declared = entry["daemon"].get("version") or "no release"
    print(f"{action}: {entry['flavor']} carries {', '.join(entry['kmis'])} (version {declared})")
    print(f"  {entry['daemon']['url']} ({entry['daemon']['size']} bytes)")
    if arguments.dry_run:
        print("  (dry run: nothing written)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
