#!/usr/bin/env python3
"""Tests for module_diagrams.py, which draws the module diagrams of the nvx
crate that doc/modules publishes.

They check how the script reads and checks cargo-modules' exports, which are
written here in its DOT form, how it merges the platforms' modules, the graphs
that it draws, the page that shows them, how it replaces an earlier run's
output, and what it runs, with a stand-in for cargo-modules and Graphviz. They
also check that doc/modules holds a page and the diagrams that it shows.
"""

from __future__ import annotations

import contextlib
import io
import re
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import module_diagrams as diagrams  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
PUBLISHED = REPO_ROOT / "doc" / "modules"
LINUX, WINDOWS = diagrams.TARGETS


def owns(owner: str, path: str) -> str:
    """The statement of a cargo-modules export in which a module contains
    another."""
    return (
        f'"{owner}" -> "{path}" [label="owns", color="#000000", style="solid"]'
        ' [constraint=true]; // "owns" edge'
    )


def export(
    modules: Mapping[str, str],
    uses: Iterable[tuple[str, str]] = (),
    *,
    extra: Iterable[str] = (),
) -> str:
    """A cargo-modules export in its DOT form: the modules with their
    visibility, the crate first, the containment that their paths imply, the
    uses, and extra statements."""
    lines = [
        "digraph {",
        "",
        "    graph [",
        '        label="nvx",',
        "    ];",
        "",
    ]
    for path, visibility in modules.items():
        if path == diagrams.CRATE:
            lines.append(
                f'    "{path}" [label="crate|{path}", fillcolor="#5397c8"];'
                ' // "crate" node'
            )
        else:
            name = path.removeprefix(f"{diagrams.CRATE}::")
            lines.append(
                f'    "{path}" [label="{visibility} mod|{name}",'
                ' fillcolor="#81c169"]; // "mod" node'
            )
    lines.extend(
        f"    {owns(path.rpartition('::')[0], path)}"
        for path in modules
        if path != diagrams.CRATE
    )
    for user, used in uses:
        lines.append(
            f'    "{user}" -> "{used}" [label="uses", color="#7f7f7f",'
            ' style="dashed"] [constraint=false]; // "uses" edge'
        )
    lines.extend(f"    {statement}" for statement in extra)
    lines += ["", "}", ""]
    return "\n".join(lines)


# The modules of a small crate on each platform: host::sys and the guest are
# Linux's alone, and host::windows is Windows'.
LINUX_MODULES = {
    "nvx": "crate",
    "nvx::error": "pub(crate)",
    "nvx::guest": "pub",
    "nvx::guest::time": "pub",
    "nvx::host": "pub",
    "nvx::host::cli": "pub",
    "nvx::host::sys": "pub(self)",
    "nvx::host::sys::socket": "pub(self)",
    "nvx::protocol": "pub",
    "nvx::protocol::nvxs": "pub(self)",
}
WINDOWS_MODULES = {
    "nvx": "crate",
    "nvx::error": "pub(crate)",
    "nvx::host": "pub",
    "nvx::host::cli": "pub",
    "nvx::host::windows": "pub(self)",
    "nvx::protocol": "pub",
    "nvx::protocol::nvxs": "pub(self)",
}
LINUX_USES = (
    ("nvx", "nvx::error"),
    ("nvx::host", "nvx::host::cli"),
    ("nvx::host::cli", "nvx::protocol"),
    ("nvx::host::cli", "nvx::protocol::nvxs"),
    ("nvx::host::sys::socket", "nvx::error"),
    ("nvx::guest::time", "nvx::protocol::nvxs"),
)
WINDOWS_USES = (
    ("nvx", "nvx::error"),
    ("nvx::host::cli", "nvx::protocol::nvxs"),
    ("nvx::host::windows", "nvx::error"),
)
EXPORTS = {
    LINUX: export(LINUX_MODULES, LINUX_USES),
    WINDOWS: export(WINDOWS_MODULES, WINDOWS_USES),
}


def crate() -> diagrams.Crate:
    return diagrams.merge(
        {
            platform: diagrams.parse(EXPORTS[platform], target)
            for platform, target in diagrams.TARGETS.items()
        }
    )


_STATEMENT = re.compile(
    r'^"(?P<tail>[^"]+)"(?: -> "(?P<head>[^"]+)")?(?: \[(?P<attributes>.*)\])?;$'
)
_ATTRIBUTE = re.compile(r'(\w+)=(?:"((?:[^"\\]|\\.)*)"|([^,\s\]]+))')


def statements(source: str) -> list[tuple[str, str | None, dict[str, str]]]:
    """The node and edge statements of a graph that the script drew, one per
    line, with their attributes, unquoted."""
    result: list[tuple[str, str | None, dict[str, str]]] = []
    for line in source.splitlines():
        match = _STATEMENT.match(line)
        if match is None:
            continue
        attributes = {
            key: (quoted.replace('\\"', '"').replace("\\\\", "\\") if quoted else bare)
            for key, quoted, bare in _ATTRIBUTE.findall(match["attributes"] or "")
        }
        result.append((match["tail"], match["head"], attributes))
    return result


def nodes(source: str) -> dict[str, dict[str, str]]:
    return {
        tail: attributes for tail, head, attributes in statements(source) if not head
    }


def edges(source: str) -> dict[tuple[str, str], dict[str, str]]:
    return {
        (tail, head): attributes
        for tail, head, attributes in statements(source)
        if head is not None and attributes.get("style") != "invis"
    }


def label(attributes: Mapping[str, str]) -> list[str]:
    return attributes["label"].split("\\n")


class ParseTests(unittest.TestCase):
    def test_exports_give_each_module_its_visibility_owner_and_uses(self):
        parsed = diagrams.parse(EXPORTS[LINUX], "linux")
        self.assertEqual(parsed.visibility, LINUX_MODULES)
        self.assertEqual(
            parsed.owner,
            {
                path: path.rpartition("::")[0]
                for path in LINUX_MODULES
                if path != diagrams.CRATE
            },
        )
        self.assertEqual(parsed.uses, frozenset(LINUX_USES))

    def test_exports_of_anything_but_modules_and_their_uses_fail(self):
        modules = {"nvx": "crate", "nvx::host": "pub"}
        cases = {
            "a type": export(
                modules,
                extra=['"nvx::host::Spec" [label="pub struct|Spec"]; // "type" node'],
            ),
            "an edge of another kind": export(
                modules,
                extra=['"nvx" -> "nvx::host" [label="x"]; // "calls" edge'],
            ),
            "a module twice": export(
                modules,
                extra=['"nvx::host" [label="pub mod|host"]; // "mod" node'],
            ),
            "no crate": export({"nvx::host": "pub"}),
            "another crate": export(
                modules, extra=['"other" [label="crate|other"]; // "crate" node']
            ),
            "a module named as the crate": export(modules).replace(
                '"nvx" [label="crate|nvx", fillcolor="#5397c8"]; // "crate" node',
                '"nvx" [label="pub mod|nvx"]; // "mod" node',
            ),
            "an edge to no module": export(modules, [("nvx", "nvx::missing")]),
            "a module without an owner": export(modules).replace(
                owns("nvx", "nvx::host"), ""
            ),
            "a module that contains another's": export(
                {"nvx": "crate", "nvx::a": "pub", "nvx::a::b": "pub"}
            ).replace(owns("nvx::a", "nvx::a::b"), owns("nvx", "nvx::a::b")),
            "a module with two owners": export(
                modules, extra=[owns("nvx", "nvx::host")]
            ),
        }
        for case, text in cases.items():
            with self.subTest(case=case):
                self.assertNotEqual(text, export(modules))
                with self.assertRaisesRegex(
                    diagrams.DiagramError, "unexpected cargo-modules export of linux"
                ):
                    diagrams.parse(text, "linux")


class MergeTests(unittest.TestCase):
    def test_the_platforms_share_their_modules_and_uses(self):
        merged = crate()
        self.assertEqual(merged.platforms, ("Linux", "Windows"))
        self.assertEqual(
            sorted(merged.modules), sorted({**LINUX_MODULES, **WINDOWS_MODULES})
        )
        both = frozenset({"Linux", "Windows"})
        self.assertEqual(merged.modules["nvx::host"].platforms, both)
        self.assertEqual(
            merged.modules["nvx::host::sys"].platforms, frozenset({"Linux"})
        )
        self.assertEqual(
            merged.modules["nvx::host::windows"].platforms, frozenset({"Windows"})
        )
        self.assertEqual(merged.uses[("nvx", "nvx::error")], both)
        self.assertEqual(
            merged.uses[("nvx::host::cli", "nvx::protocol")], frozenset({"Linux"})
        )
        self.assertEqual(merged.owner["nvx::host::windows"], "nvx::host")
        self.assertEqual(
            merged.roots(),
            ["nvx::error", "nvx::guest", "nvx::host", "nvx::protocol"],
        )
        self.assertEqual(
            merged.subtree("nvx::host"),
            [
                "nvx::host",
                "nvx::host::cli",
                "nvx::host::sys",
                "nvx::host::sys::socket",
                "nvx::host::windows",
            ],
        )

    def test_only_the_outermost_module_of_a_platform_names_it(self):
        merged = crate()
        expected = {
            "nvx": None,
            "nvx::guest": "Linux",
            "nvx::guest::time": None,
            "nvx::host": None,
            "nvx::host::sys": "Linux",
            "nvx::host::sys::socket": None,
            "nvx::host::windows": "Windows",
        }
        for path, platforms in expected.items():
            with self.subTest(path=path):
                self.assertEqual(merged.only(path), platforms)

    def test_a_visibility_that_differs_names_each_platform(self):
        merged = diagrams.merge(
            {
                "Linux": diagrams.parse(
                    export({"nvx": "crate", "nvx::a": "pub"}), "linux"
                ),
                "Windows": diagrams.parse(
                    export({"nvx": "crate", "nvx::a": "pub(crate)"}), "windows"
                ),
            }
        )
        self.assertEqual(
            merged.modules["nvx::a"].visibility, "pub on Linux, pub(crate) on Windows"
        )
        drawn = nodes(diagrams.dependencies(merged))
        self.assertIn("dashed", drawn["nvx::a"]["style"])
        self.assertEqual(
            label(drawn["nvx::a"]), ["a", "pub on Linux, pub(crate) on Windows"]
        )

    def test_labels_are_quoted_for_graphviz(self):
        self.assertEqual(diagrams.quote('a"b\\c\nd'), '"a\\"b\\\\c\\nd"')


class GraphTests(unittest.TestCase):
    def test_boxes_show_their_visibility_and_platforms(self):
        source = diagrams.hierarchy(crate(), "nvx::host")
        drawn = nodes(source)
        # Public modules are solid, private ones dashed and unnamed.
        self.assertEqual(label(drawn["nvx::host"]), ["nvx::host"])
        self.assertNotIn("dashed", drawn["nvx::host::cli"]["style"])
        self.assertEqual(label(drawn["nvx::host::sys"]), ["sys", "Linux only"])
        self.assertIn("dashed", drawn["nvx::host::sys"]["style"])
        self.assertEqual(label(drawn["nvx::host::sys::socket"]), ["socket"])
        self.assertEqual(
            label(drawn["nvx::host::windows"]), ["windows", "Windows only"]
        )
        # Any other visibility is named.
        error = nodes(diagrams.dependencies(crate()))["nvx::error"]
        self.assertEqual(label(error), ["error", "pub(crate)"])
        self.assertIn("dashed", error["style"])
        for path, attributes in drawn.items():
            with self.subTest(path=path):
                self.assertIn(path, attributes["tooltip"])
                self.assertEqual(
                    (attributes["fillcolor"], attributes["color"]),
                    diagrams.COLORS["host"],
                )

    def test_hierarchies_draw_the_containment_in_a_top_level_module(self):
        merged = crate()
        source = diagrams.hierarchy(merged, "nvx::host")
        self.assertEqual(set(nodes(source)), set(merged.subtree("nvx::host")))
        self.assertEqual(
            set(edges(source)),
            {
                (merged.owner[path], path)
                for path in merged.subtree("nvx::host")
                if path != "nvx::host"
            },
        )
        # Children keep the order of their paths.
        self.assertIn("ordering=out", source)

    def test_the_overview_shows_every_top_level_module_in_the_crate(self):
        merged = crate()
        source = diagrams.overview(merged)
        drawn = nodes(source)
        self.assertEqual(set(drawn), set(merged.roots()))
        self.assertEqual(
            label(drawn["nvx::host"]),
            ["host", diagrams.DESCRIPTIONS["host"], "4 nested modules"],
        )
        self.assertEqual(
            label(drawn["nvx::guest"]),
            ["guest", diagrams.DESCRIPTIONS["guest"], "1 nested module", "Linux only"],
        )
        self.assertEqual(
            label(drawn["nvx::error"]),
            ["error", diagrams.DESCRIPTIONS["error"], "pub(crate)"],
        )
        self.assertIn('subgraph "cluster_nvx"', source)
        self.assertEqual(edges(source), {})

    def test_the_dependencies_count_the_uses_between_top_level_modules(self):
        source = diagrams.dependencies(crate())
        counts = {
            pair: attributes["label"] for pair, attributes in edges(source).items()
        }
        self.assertEqual(
            counts,
            {
                ("nvx", "nvx::error"): "1",
                ("nvx::guest", "nvx::protocol"): "1",
                # host::sys on Linux and host::windows on Windows.
                ("nvx::host", "nvx::error"): "2",
                ("nvx::host", "nvx::protocol"): "2",
            },
        )
        self.assertEqual(
            edges(source)[("nvx::guest", "nvx::protocol")]["color"],
            diagrams.COLORS["guest"][1],
        )
        self.assertEqual(set(nodes(source)), {"nvx", *crate().roots()})

    def test_the_page_shows_the_overview_the_dependencies_and_each_hierarchy(self):
        drawn = diagrams.diagrams(crate())
        # error contains no module, so it has no hierarchy.
        self.assertEqual(
            [diagram.name for diagram in drawn],
            [
                "overview.svg",
                "dependencies.svg",
                "nvx-guest.svg",
                "nvx-host.svg",
                "nvx-protocol.svg",
            ],
        )
        self.assertEqual(
            [diagram.root for diagram in drawn],
            [None, None, "nvx::guest", "nvx::host", "nvx::protocol"],
        )


class PageTests(unittest.TestCase):
    def page(
        self, output: Path = diagrams.DEFAULT_OUTPUT, tools: str = "the tools"
    ) -> str:
        merged = crate()
        return diagrams.page(merged, diagrams.diagrams(merged), output, tools)

    def links(self, output: Path) -> dict[str, str]:
        """The links of the page in the output directory, by their text."""
        text = " ".join(self.page(output).split())
        return dict(re.findall(r"(?<!!)\[([^\]]+)\]\(([^)]+)\)", text))

    def test_the_page_shows_every_diagram_in_order(self):
        text = self.page()
        self.assertTrue(text.startswith(diagrams.MARKER + "\n\n# Module diagrams\n"))
        self.assertEqual(
            re.findall(r"!\[[^\]]*\]\(([^)]+)\)", text),
            [diagram.name for diagram in diagrams.diagrams(crate())],
        )
        self.assertEqual(
            re.findall(r"^#+ .*$", text, re.M),
            [
                "# Module diagrams",
                "## Overview",
                "## Dependencies",
                "## Hierarchies",
                "### `nvx::guest`",
                "### `nvx::host`",
                "### `nvx::protocol`",
            ],
        )

    def test_the_page_says_what_the_diagrams_cover(self):
        text = " ".join(self.page(tools="TOOLS").split())
        self.assertIn("as TOOLS.", text)
        for feature in diagrams.FEATURES:
            self.assertIn(f"`{feature}`", text)
        for platform, target in diagrams.TARGETS.items():
            self.assertIn(f"{platform} (`{target}`)", text)
        self.assertIn("`nvx::host`, in", text)
        self.assertIn("contains 4 modules.", text)

    def test_the_page_links_lead_from_its_directory_to_the_files(self):
        nested = REPO_ROOT / "build" / "nested" / "modules"
        for output, up in ((diagrams.DEFAULT_OUTPUT, "../.."), (nested, "../../..")):
            with self.subTest(output=output):
                links = self.links(output)
                self.assertEqual(links["`nvx` crate"], f"{up}/nvx-rs/README.md")
                self.assertEqual(
                    links["`nvx-rs/src/host/mod.rs`"], f"{up}/nvx-rs/src/host/mod.rs"
                )
                for target in links.values():
                    path = (output / target.partition("#")[0]).resolve()
                    self.assertTrue(path.is_file(), path)

    def test_an_inline_module_has_no_source_link(self):
        merged = diagrams.merge(
            {
                "Linux": diagrams.parse(
                    export(
                        {"nvx": "crate", "nvx::inline": "pub", "nvx::inline::a": "pub"}
                    ),
                    "linux",
                )
            }
        )
        output = diagrams.DEFAULT_OUTPUT
        text = " ".join(
            diagrams.page(merged, diagrams.diagrams(merged), output, "x").split()
        )
        self.assertIn("`nvx::inline` contains 1 module.", text)


def _svg(title: str) -> str:
    return f'<svg xmlns="http://www.w3.org/2000/svg"><title>{title}</title></svg>\n'


class FakeTools:
    """cargo-modules and Graphviz: each export command prints the export of its
    target, and dot draws an SVG titled with its graph's name."""

    def __init__(self, exports: Mapping[str, str] = EXPORTS) -> None:
        self.exports = {
            tuple(diagrams.export_command(diagrams.TARGETS[platform])): text
            for platform, text in exports.items()
        }
        self.commands: list[list[str]] = []
        self.sources: list[str] = []
        self.versions = True
        self.svg = True

    def __call__(self, command: Sequence[str], stdin: str | None) -> diagrams.Output:
        self.commands.append(list(command))
        if tuple(command) in self.exports:
            return diagrams.Output(self.exports[tuple(command)], "")
        if command[1:] == ["-Tsvg"] and stdin is not None:
            self.sources.append(stdin)
            name = re.match(r'digraph "([^"]+)"', stdin)
            assert name is not None
            return diagrams.Output(
                _svg(name[1]) if self.svg else "<html/>", "warning: none\n"
            )
        if not self.versions:
            raise diagrams.DiagramError("no version")
        if command == ["cargo", "modules", "--version"]:
            return diagrams.Output("cargo-modules 9.9.9\n", "")
        if command[1:] == ["-V"]:
            return diagrams.Output("", "dot - graphviz version 1.2.3 (0)\n")
        raise AssertionError(f"unexpected command {command}")


class DrawTests(unittest.TestCase):
    def draw(self, output: Path, tools: FakeTools) -> list[str]:
        with contextlib.redirect_stderr(io.StringIO()):
            return diagrams.draw(output, "dot", tools)

    def test_draw_exports_each_platform_and_writes_the_page_and_diagrams(self):
        tools = FakeTools()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "modules"
            names = self.draw(output, tools)
            drawn = diagrams.diagrams(crate())
            self.assertEqual(
                names, sorted([diagrams.PAGE, *(diagram.name for diagram in drawn)])
            )
            self.assertEqual(sorted(path.name for path in output.iterdir()), names)
            for diagram in drawn:
                with self.subTest(diagram=diagram.name):
                    root = ET.parse(output / diagram.name).getroot()
                    self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
            page = (output / diagrams.PAGE).read_text(encoding="utf-8")
        self.assertEqual(
            tools.commands[: len(diagrams.TARGETS)],
            [diagrams.export_command(target) for target in diagrams.TARGETS.values()],
        )
        self.assertEqual(tools.sources, [diagram.source for diagram in drawn])
        flat = " ".join(page.split())
        self.assertIn("cargo-modules) 9.9.9 finds them and Graphviz 1.2.3 draws", flat)

    def test_the_page_names_no_version_that_a_tool_does_not_report(self):
        tools = FakeTools()
        tools.versions = False
        with tempfile.TemporaryDirectory() as directory:
            self.draw(Path(directory), tools)
            page = (Path(directory) / diagrams.PAGE).read_text(encoding="utf-8")
        self.assertIn("finds them and Graphviz draws them", " ".join(page.split()))

    def test_a_failed_drawing_leaves_the_output_unchanged(self):
        tools = FakeTools()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.draw(output, tools)
            before = {path.name: path.read_bytes() for path in output.iterdir()}
            failing = FakeTools(
                {LINUX: export({"nvx": "crate"}), WINDOWS: EXPORTS[WINDOWS]}
            )
            failing.svg = False
            with self.assertRaisesRegex(diagrams.DiagramError, "no SVG"):
                self.draw(output, failing)
            broken = FakeTools({LINUX: "digraph {}", WINDOWS: EXPORTS[WINDOWS]})
            with self.assertRaisesRegex(diagrams.DiagramError, "export"):
                self.draw(output, broken)
            after = {path.name: path.read_bytes() for path in output.iterdir()}
        self.assertEqual(after, before)

    def test_exports_cover_the_library_with_the_features_of_the_page(self):
        for target in diagrams.TARGETS.values():
            command = diagrams.export_command(target)
            with self.subTest(target=target):
                self.assertEqual(
                    command[:4], ["cargo", "modules", "dependencies", "--lib"]
                )
                options = dict(zip(command[4:], command[5:], strict=False))
                self.assertEqual(options["--manifest-path"], str(diagrams.MANIFEST))
                self.assertEqual(options["--features"], ",".join(diagrams.FEATURES))
                self.assertEqual(options["--target"], target)
                for excluded in ("fns", "traits", "types", "externs", "sysroot"):
                    self.assertIn(f"--no-{excluded}", command)
                self.assertNotIn("--no-uses", command)
                self.assertNotIn("--no-owns", command)

    def test_a_missing_cargo_modules_names_the_release_to_install(self):
        stderr = io.StringIO()
        with (
            patch.object(diagrams.shutil, "which", return_value=None),
            contextlib.redirect_stderr(stderr),
        ):
            status = diagrams.main(["--output", str(REPO_ROOT / "build" / "unused")])
        self.assertEqual(status, 1)
        self.assertIn(
            f"cargo-modules --version {diagrams.CARGO_MODULES_VERSION}",
            stderr.getvalue(),
        )


class ReplaceTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.files = {diagrams.PAGE: diagrams.MARKER + "\npage\n", "a.svg": "<svg/>\n"}

    def contents(self, output: Path) -> dict[str, bytes]:
        return {path.name: path.read_bytes() for path in output.iterdir()}

    def test_an_earlier_run_is_replaced_with_lf_line_endings(self):
        output = self.root / "new" / "modules"
        diagrams.replace(output, self.files)
        (output / "stale.svg").write_text("<svg/>\n", encoding="utf-8")
        diagrams.replace(output, self.files | {"b.svg": "<svg>\n</svg>\n"})
        self.assertEqual(
            self.contents(output),
            {
                diagrams.PAGE: (diagrams.MARKER + "\npage\n").encode(),
                "a.svg": b"<svg/>\n",
                "b.svg": b"<svg>\n</svg>\n",
            },
        )
        empty = self.root / "empty"
        empty.mkdir()
        diagrams.replace(empty, self.files)
        self.assertEqual(sorted(self.contents(empty)), ["README.md", "a.svg"])

    def test_directories_that_hold_more_than_an_earlier_run_are_refused(self):
        cases: dict[str, dict[str, str]] = {
            "another file": {diagrams.PAGE: diagrams.MARKER + "\n", "notes.txt": ""},
            "another page": {diagrams.PAGE: "# Notes\n", "a.svg": ""},
            "no page": {"a.svg": "<svg/>\n"},
        }
        for case, files in cases.items():
            with self.subTest(case=case):
                output = self.root / case
                output.mkdir()
                for name, text in files.items():
                    (output / name).write_text(text, encoding="utf-8")
                before = self.contents(output)
                with self.assertRaisesRegex(diagrams.DiagramError, "--output"):
                    diagrams.replace(output, self.files)
                self.assertEqual(self.contents(output), before)
        nested = self.root / "nested"
        (nested / "sub").mkdir(parents=True)
        with self.assertRaisesRegex(diagrams.DiagramError, "sub"):
            diagrams.replace(nested, self.files)
        regular = self.root / "file"
        regular.write_text("", encoding="utf-8")
        with self.assertRaisesRegex(diagrams.DiagramError, "not a directory"):
            diagrams.replace(regular, self.files)

    def test_a_symbolic_link_is_refused_rather_than_written_through(self):
        output = self.root / "linked"
        diagrams.replace(output, self.files)
        target = self.root / "outside.txt"
        target.write_text("outside\n", encoding="utf-8")
        try:
            (output / "b.svg").symlink_to(target)
        except OSError:
            self.skipTest("this host cannot create symbolic links")
        with self.assertRaisesRegex(diagrams.DiagramError, "b.svg"):
            diagrams.replace(output, self.files | {"b.svg": "<svg/>\n"})
        self.assertEqual(target.read_text(encoding="utf-8"), "outside\n")


class PublishedTests(unittest.TestCase):
    def test_doc_modules_holds_the_page_and_the_diagrams_that_it_shows(self):
        page = (PUBLISHED / diagrams.PAGE).read_text(encoding="utf-8")
        self.assertTrue(page.startswith(diagrams.MARKER + "\n"))
        images = re.findall(r"!\[[^\]]*\]\(([^)]+)\)", page)
        self.assertEqual(images[:2], ["overview.svg", "dependencies.svg"])
        self.assertEqual(
            sorted(path.name for path in PUBLISHED.iterdir()),
            sorted([diagrams.PAGE, *images]),
        )
        for image in images:
            with self.subTest(image=image):
                root = ET.parse(PUBLISHED / image).getroot()
                self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")


if __name__ == "__main__":
    unittest.main()
