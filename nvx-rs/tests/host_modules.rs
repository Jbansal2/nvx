//! The layering of `nvx::host`: its direct children depend on one another without cycles, so that
//! each builds only on those beneath it.
//!
//! The test reads the sources of `src/host/` as text, with the crate root's imports of host items,
//! such as `nvx::Artifacts`. It blanks their comments and literals, follows the modules that files
//! and inline `mod` blocks declare, and leaves out test-only code: what a `cfg` that requires
//! `test` guards, with the attributes of that code and the files of the modules that it declares,
//! `#[test]` functions, and inline `tests` modules. It leaves out guarded code only as far as its
//! tokens show where that code ends: an item, a statement that ends with a `;`, a macro
//! invocation, a block, `if`, `match`, or loop, where the start of the file or a `{`, `}`, or `;`
//! before it shows that one starts, or a field, parameter, variant, or arm of the list that
//! declares it. Other guarded code, such as a field of a struct expression or a parameter of a
//! closure, counts, so that the test may find a dependency in test-only code, but never misses one
//! in production code.
//!
//! Each `crate::`, `super::`, and `self::` path that remains, in a `use` tree or elsewhere, also in
//! an attribute or, with its escapes decoded, in a string of one, such as serde's `with = "..."`,
//! names the longest module that it starts with, or an item that the crate root or `host` imports
//! at module level, and so the child of `host` that holds it. An import of the crate root or `host`
//! may name what either of them imports, by a path or, in its own module, by the name alone, in any
//! order, and `cfg`s may choose between imports of the same name from different children, or
//! between such an import and a module: a path through such a name depends on each child that any
//! of those imports takes it from. A macro that a child exports with `#[macro_export]` is an item
//! of the crate root, as `crate::NAME!`, which that child holds, among the names of macros alone: a
//! path names it with the `!` of an invocation, and an import of its name takes it beside other
//! items of that name. A raw identifier, such as `r#type`, names what `type` would. A path within a
//! child, to `host` itself, or in documentation, such as `#[doc = "..."]`, as in a doc comment, is
//! no dependency. Since the test reads text, the code of every target and feature counts. A cycle
//! fails the test, which names one reference for each dependency in it.
//!
//! Code whose dependencies the test cannot follow fails it too: a `#[path]` attribute, a file
//! that no `mod` declares, an import of `host` or the crate root itself, such as `extern crate
//! self as this;`, whose names would hide the children that the code uses, a `#[macro_use]`
//! attribute in `host`, whose macros code would use without a path, and a glob import into either
//! from a child.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

/// A file that the test reads.
struct Source {
    /// The file's path in the crate, with `/` separators, such as `src/host/store/mod.rs`.
    path: String,
    /// The file's text.
    text: String,
}

/// A token of blanked source text.
#[derive(Clone, Copy, Debug)]
struct Token<'a> {
    /// An identifier, keyword, or number; `::` or `=>`; or another punctuation character.
    text: &'a str,
    /// The token's line, from 1.
    line: usize,
    /// The index of the token's first byte in the text.
    offset: usize,
}

/// A path that a file writes: in a `use` tree, or a `crate::`, `super::`, or `self::` path
/// elsewhere, also in an attribute or in a string of one.
#[derive(Debug)]
struct Reference {
    /// The module in which the path is written, from the crate root.
    module: Vec<String>,
    /// The path's segments, as written, with the prefixes of its `use` tree.
    segments: Vec<String>,
    /// How the path imports what it names, if a `use` declaration holds it.
    kind: Kind,
    /// The line of the path's last segment.
    line: usize,
    /// Whether test-only code of its file holds the path.
    test: bool,
    /// Whether a function body or another block holds the path, rather than modules alone.
    local: bool,
}

/// A path that code writes outside `use` trees: its segments, as written, and the line of its
/// last segment.
type WrittenPath = (Vec<String>, usize);

/// How a path imports what it names.
#[derive(Debug, PartialEq, Eq)]
enum Kind {
    /// It imports nothing: it is not in a `use` declaration.
    Path,
    /// A `use` declaration imports what the path names, under a name, or under none for `as _`.
    Import(Option<String>),
    /// A `use` declaration imports the contents of what the path names, through a glob.
    Glob,
}

/// What the test finds in a file.
#[derive(Debug, Default)]
struct Facts {
    /// The modules that `mod NAME;` declarations place in files of their own, each with whether
    /// test-only code declares it.
    declared: Vec<(Vec<String>, bool)>,
    /// The modules of the file's inline `mod NAME { ... }` blocks.
    inline: Vec<Vec<String>>,
    /// The file's references.
    references: Vec<Reference>,
    /// The lines of the file's `#[path]` attributes, each with the module in which it is written
    /// and the module that it places, if a `mod` follows it.
    path_attributes: Vec<(Vec<String>, usize, Option<String>)>,
    /// The lines of the file's `#[macro_use]` attributes, each with the module in which it is
    /// written.
    macro_uses: Vec<(Vec<String>, usize)>,
    /// The macros that the file exports at the crate root with `#[macro_export]`, each with the
    /// module that defines it and whether test-only code exports it.
    exported: Vec<(Vec<String>, String, bool)>,
}

impl Facts {
    /// Adds `paths`, each with its segments and the line of its last segment, which `module`
    /// writes outside `use` trees, to the references: as test-only ones if `test`, and as ones
    /// that a block holds if `local`.
    fn add_paths(&mut self, module: &[String], paths: Vec<WrittenPath>, test: bool, local: bool) {
        for (segments, line) in paths {
            self.references.push(Reference {
                module: module.to_vec(),
                segments,
                kind: Kind::Path,
                line,
                test,
                local,
            });
        }
    }
}

/// A bracketed region of a file that the parser is in.
struct Frame {
    /// Whether the region's code is test-only.
    test: bool,
    /// The name of the inline module whose body the region is, if it is one.
    module: Option<String>,
    /// What the region lists.
    list: List,
}

/// What a bracketed region lists, which tells where test-only code in it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum List {
    /// The fields of a struct, union, or variant, or the parameters of a function: each ends at a
    /// comma outside the angle brackets of its type.
    Fields,
    /// The variants of an enum: each ends at a comma.
    Variants,
    /// The arms of a `match`: each ends after the block that follows its `=>`, or at a comma.
    Arms,
    /// Items, statements, or expressions.
    Code,
}

/// The dependencies between the direct children of `host`.
#[derive(Debug, Default)]
struct Graph {
    /// For each dependency, from a child to another, the first reference that makes it, in the
    /// order of the files' paths and their lines.
    edges: BTreeMap<(String, String), Example>,
}

/// A reference that makes a dependency.
#[derive(Debug)]
struct Example {
    /// The file and line of the reference, such as `src/host/store/mod.rs:242`.
    location: String,
    /// The path that the reference writes, such as `super::spawn::Launched`.
    path: String,
}

/// What a path names, for the graph.
#[derive(Debug, PartialEq, Eq)]
enum Target {
    /// The crate root itself.
    Root,
    /// `host` itself.
    Host,
    /// Children of `host`, or something within them: the child that a path into one names, or
    /// every child from which the crate root or `host` imports the name that a path names through
    /// them, since `cfg`s may choose between imports of the same name.
    Children(BTreeSet<String>),
    /// Something outside `host`.
    Outside,
}

/// The modules of the crate that the test knows, and the names that the crate root and `host`
/// import from the children of `host`.
#[derive(Default)]
struct Modules {
    /// Every module that a file, an inline `mod` block, or a `mod` declaration makes, from the
    /// crate root, which is the empty path.
    paths: BTreeSet<Vec<String>>,
    /// The children of `host` from which the crate root, `[]`, or `host` imports each name: all of
    /// them, where `cfg`s choose between imports of the same name. The name of a macro ends with
    /// a `!`, as `shared!` does, so that it hides no module or other item of the same name.
    imports: BTreeMap<(Vec<String>, String), BTreeSet<String>>,
}

/// Returns `path` as the path of a macro, whose last segment ends with a `!`.
fn as_macro(path: &[String]) -> Vec<String> {
    let mut path = path.to_vec();
    if let Some(name) = path.last_mut() {
        name.push('!');
    }
    path
}

impl Modules {
    /// Returns the path from the crate root that `segments`, written in `module`, name, if they
    /// start with `crate`, `super`, or `self`, or, for an `import`, with a module or an imported
    /// name of `module`, as `use host::artifacts::Artifacts;` and then `use Artifacts as Alias;` at
    /// the crate root do.
    fn absolute(
        &self,
        module: &[String],
        segments: &[String],
        import: bool,
    ) -> Option<Vec<String>> {
        let (first, rest) = segments.split_first()?;
        let imported = |name: String| self.imports.contains_key(&(module.to_vec(), name));
        let mut path = match first.as_str() {
            "crate" => Vec::new(),
            "self" | "super" => module.to_vec(),
            _ if import
                && (self.paths.contains(&[module, &segments[..1]].concat())
                    || imported(first.clone())
                    || imported(format!("{first}!"))) =>
            {
                return Some([module, segments].concat());
            }
            _ => return None,
        };
        let mut rest = rest;
        if first == "super" {
            path.pop()?;
            while let Some((next, tail)) = rest.split_first()
                && next == "super"
            {
                path.pop()?;
                rest = tail;
            }
        }
        path.extend_from_slice(rest);
        Some(path)
    }

    /// Returns what `path`, from the crate root, names: the longest known module that it starts
    /// with, and, in the crate root or `host`, an item that they import. A module of the crate
    /// root or `host` hides no import of the same name, which other `cfg`s may choose instead.
    fn target(&self, path: &[String]) -> Target {
        let mut children = BTreeSet::new();
        for scope in [0, 1] {
            let (module, rest) = path.split_at(scope.min(path.len()));
            if (module.is_empty() || module == ["host"])
                && let Some(name) = rest.first()
                && let Some(imported) = self.imports.get(&(module.to_vec(), name.clone()))
            {
                children.extend(imported.iter().cloned());
            }
        }
        let known = (0..=path.len())
            .rev()
            .find(|&length| self.paths.contains(&path[..length]))
            .unwrap_or(0);
        let (module, rest) = path.split_at(known);
        match module {
            [host, child, ..] if host == "host" => {
                children.insert(child.clone());
            }
            _ if !children.is_empty() => {}
            [] if rest.is_empty() => return Target::Root,
            [host] if host == "host" && rest.is_empty() => return Target::Host,
            _ => return Target::Outside,
        }
        Target::Children(children)
    }
}

/// Reads `src/lib.rs` and the files beneath `src/host/`.
fn read_sources() -> Vec<Source> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths = vec![root.join("src").join("lib.rs")];
    add_files(&root.join("src").join("host"), &mut paths);
    paths
        .iter()
        .map(|path| Source {
            path: path
                .strip_prefix(root)
                .unwrap()
                .components()
                .map(|component| component.as_os_str().to_str().unwrap())
                .collect::<Vec<_>>()
                .join("/"),
            text: fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display())),
        })
        .collect()
}

/// Adds the paths of the `.rs` files beneath `directory` to `paths`.
fn add_files(directory: &Path, paths: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()));
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            add_files(&path, paths);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            paths.push(path);
        }
    }
}

/// Returns whether `byte` can be part of an identifier, a keyword, or a number.
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || !byte.is_ascii()
}

/// Returns whether `text`, a token, is an identifier or a keyword.
fn is_identifier(text: &str) -> bool {
    text.bytes()
        .next()
        .is_some_and(|byte| is_word_byte(byte) && !byte.is_ascii_digit())
}

/// Returns `text` with its comments and literals blanked: every byte of them but line feeds
/// becomes a space, so that the code around them keeps its lines.
fn blank(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut blanked = bytes.to_vec();
    let mut at = 0;
    while at < bytes.len() {
        match literal_end(bytes, at) {
            Some(end) => {
                for byte in &mut blanked[at..end] {
                    if *byte != b'\n' {
                        *byte = b' ';
                    }
                }
                at = end;
            }
            None => at += 1,
        }
    }
    String::from_utf8(blanked).expect("blanking replaces whole characters")
}

/// Returns the end of the comment, string, or character literal that starts at `at`, if one
/// does: a line, doc, or nested block comment; a string, byte string, or C string, with escapes,
/// or a raw one of them with any number of `#`; or a character or byte literal, but not a
/// lifetime or a label.
fn literal_end(bytes: &[u8], at: usize) -> Option<usize> {
    let rest = &bytes[at..];
    if rest.starts_with(b"//") {
        return Some(find(bytes, at, b"\n").unwrap_or(bytes.len()));
    }
    if rest.starts_with(b"/*") {
        return Some(block_comment_end(bytes, at));
    }
    match rest {
        [b'"', ..] => Some(quoted_end(bytes, at + 1)),
        [b'\'', ..] => character_end(bytes, at),
        // A prefix such as `b` or `r` starts a literal only where no identifier ends.
        _ if at > 0 && is_word_byte(bytes[at - 1]) => None,
        [b'b' | b'c', b'"', ..] => Some(quoted_end(bytes, at + 2)),
        [b'b', b'\'', ..] => character_end(bytes, at + 1),
        [b'r', ..] => raw_end(bytes, at + 1),
        [b'b' | b'c', b'r', ..] => raw_end(bytes, at + 2),
        _ => None,
    }
}

/// Returns the position of the first `needle` at or after `from` in `bytes`.
fn find(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    bytes
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| from + position)
}

/// Returns the end of the block comment that starts at `start`, after the `*/` that closes it,
/// with the comments nested in it.
fn block_comment_end(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0;
    let mut at = start;
    while at < bytes.len() {
        if bytes[at..].starts_with(b"/*") {
            depth += 1;
            at += 2;
        } else if bytes[at..].starts_with(b"*/") {
            depth -= 1;
            at += 2;
            if depth == 0 {
                return at;
            }
        } else {
            at += 1;
        }
    }
    bytes.len()
}

/// Returns the end of the string whose text starts at `start`, after its closing quote, which
/// no backslash escapes.
fn quoted_end(bytes: &[u8], start: usize) -> usize {
    let mut at = start;
    while at < bytes.len() {
        match bytes[at] {
            b'\\' => at += 2,
            b'"' => return at + 1,
            _ => at += 1,
        }
    }
    bytes.len()
}

/// Returns the end of the character literal whose opening quote is at `quote`, or `None` if the
/// quote starts a lifetime or a label, such as `'a` or `'outer`.
fn character_end(bytes: &[u8], quote: usize) -> Option<usize> {
    let first = *bytes.get(quote + 1)?;
    if first == b'\\' {
        // The escaped character follows the backslash, so the closing quote comes after it.
        return Some(find(bytes, quote + 3, b"'").map_or(bytes.len(), |close| close + 1));
    }
    let width = match first {
        0xf0..=0xff => 4,
        0xe0..=0xef => 3,
        0xc0..=0xdf => 2,
        _ => 1,
    };
    (bytes.get(quote + 1 + width) == Some(&b'\'')).then_some(quote + 2 + width)
}

/// Returns the end of the raw string whose `#` signs, if any, start at `start`, or `None` if no
/// raw string starts there, as in a raw identifier such as `r#type`.
fn raw_end(bytes: &[u8], start: usize) -> Option<usize> {
    let hashes = bytes[start..]
        .iter()
        .take_while(|&&byte| byte == b'#')
        .count();
    let open = start + hashes;
    if bytes.get(open) != Some(&b'"') {
        return None;
    }
    let mut close = vec![b'"'];
    close.resize(1 + hashes, b'#');
    Some(find(bytes, open + 1, &close).map_or(bytes.len(), |at| at + close.len()))
}

/// Splits blanked text into tokens. A raw identifier, such as `r#type`, is one token, and so are a
/// lifetime and a label, such as `'static` and `'outer`, whose quotes blanking left.
fn tokenize(text: &str) -> Vec<Token<'_>> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut line = 1;
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        if byte == b'\n' {
            line += 1;
            at += 1;
            continue;
        }
        if byte.is_ascii_whitespace() {
            at += 1;
            continue;
        }
        let word = |from: usize| {
            bytes[from..]
                .iter()
                .take_while(|&&byte| is_word_byte(byte))
                .count()
        };
        let raw = bytes[at..].starts_with(b"r#")
            && bytes
                .get(at + 2)
                .is_some_and(|&next| is_word_byte(next) && !next.is_ascii_digit());
        let length = if raw {
            2 + word(at + 2)
        } else if byte == b'\'' && bytes.get(at + 1).copied().is_some_and(is_word_byte) {
            1 + word(at + 1)
        } else if is_word_byte(byte) {
            word(at)
        } else if bytes[at..].starts_with(b"::") || bytes[at..].starts_with(b"=>") {
            2
        } else {
            1
        };
        tokens.push(Token {
            text: &text[at..at + length],
            line,
            offset: at,
        });
        at += length;
    }
    tokens
}

/// Returns the name that the identifier `token` makes, without the `r#` of a raw identifier.
fn unraw(token: &str) -> String {
    plain(token).to_owned()
}

/// Returns the name that the identifier `token` makes, as [`unraw`] does, borrowed.
fn plain(token: &str) -> &str {
    token.strip_prefix("r#").unwrap_or(token)
}

/// Returns the text of `tokens[at]`, or an empty text past the end.
fn text_at<'a>(tokens: &[Token<'a>], at: usize) -> &'a str {
    tokens.get(at).map_or("", |token| token.text)
}

/// Returns the `crate::`, `super::`, or `self::` path that starts at `tokens[at]`, if one does:
/// its segments, the index of its last segment, and the index after it. The last segment of a
/// macro's path, which a `!` and the macro's arguments follow, ends with that `!`, since macros
/// have names of their own, apart from those of modules and other items.
fn qualified_path(tokens: &[Token<'_>], at: usize) -> Option<(Vec<String>, usize, usize)> {
    let first = text_at(tokens, at);
    if !matches!(first, "crate" | "super" | "self") || text_at(tokens, at + 1) != "::" {
        return None;
    }
    let mut segments = vec![first.to_owned()];
    let mut last = at;
    let mut end = at + 1;
    while text_at(tokens, end) == "::" && is_identifier(text_at(tokens, end + 1)) {
        segments.push(unraw(tokens[end + 1].text));
        last = end + 1;
        end += 2;
    }
    if text_at(tokens, end) == "!"
        && matches!(text_at(tokens, end + 1), "(" | "[" | "{")
        && let Some(name) = segments.last_mut()
    {
        name.push('!');
    }
    Some((segments, last, end))
}

/// Returns the `crate::`, `super::`, and `self::` paths in `tokens`, each with its segments and the
/// line that `line_of` gives for its last segment.
fn qualified_paths(
    tokens: &[Token<'_>],
    line_of: impl Fn(&Token<'_>) -> usize,
) -> Vec<WrittenPath> {
    let mut paths = Vec::new();
    let mut at = 0;
    while at < tokens.len() {
        match qualified_path(tokens, at) {
            Some((segments, last, end)) => {
                paths.push((segments, line_of(&tokens[last])));
                at = end;
            }
            None => at += 1,
        }
    }
    paths
}

/// Returns the index of the token after the visibility, such as `pub(crate)`, that starts at
/// `tokens[at]`, or `at` if no visibility starts there.
fn after_visibility(tokens: &[Token<'_>], mut at: usize) -> usize {
    if text_at(tokens, at) == "pub" {
        at += 1;
        if text_at(tokens, at) == "(" {
            while !matches!(text_at(tokens, at), ")" | "") {
                at += 1;
            }
            at += 1;
        }
    }
    at
}

/// Returns the attribute that starts at `tokens[at]`, a `#`, if one does: the index after it,
/// whether it is an inner attribute, `#![...]`, and the tokens within its brackets.
fn attribute<'t, 'a>(tokens: &'t [Token<'a>], at: usize) -> Option<(usize, bool, &'t [Token<'a>])> {
    let inner = text_at(tokens, at + 1) == "!";
    let open = at + 1 + usize::from(inner);
    if text_at(tokens, open) != "[" {
        return None;
    }
    let mut depth = 0;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        match token.text {
            "[" => depth += 1,
            "]" => {
                depth -= 1;
                if depth == 0 {
                    return Some((index + 1, inner, &tokens[open + 1..index]));
                }
            }
            _ => {}
        }
    }
    Some((tokens.len(), inner, &tokens[open + 1..]))
}

/// Returns whether an attribute, by the tokens within its brackets, makes what it guards
/// test-only: `#[test]`, or a `cfg` whose predicate requires `test`. Raw identifiers, such as
/// `r#cfg`, name what they would without `r#`, here and in the other checks of attributes.
fn guards_test(attribute: &[Token<'_>]) -> bool {
    match attribute {
        [only] => plain(only.text) == "test",
        [name, open, predicate @ ..] if plain(name.text) == "cfg" && open.text == "(" => {
            requires_test(predicate, &mut 0)
        }
        _ => false,
    }
}

/// Returns whether the `cfg` predicate at `tokens[*at]` holds only where `test` does, and moves
/// `*at` past it. Such a predicate is `test`, an `all` of predicates of which one is such, or an
/// `any` of predicates that all are; `not(test)` is not.
fn requires_test(tokens: &[Token<'_>], at: &mut usize) -> bool {
    let name = plain(text_at(tokens, *at));
    *at += 1;
    match text_at(tokens, *at) {
        // The value of `key = "value"` is a string, which blanking removed.
        "=" => {
            *at += 1;
            false
        }
        "(" => {
            *at += 1;
            let mut predicates = Vec::new();
            while !matches!(text_at(tokens, *at), ")" | "") {
                predicates.push(requires_test(tokens, at));
                if text_at(tokens, *at) == "," {
                    *at += 1;
                }
            }
            *at += 1;
            match name {
                "all" => predicates.contains(&true),
                "any" => !predicates.is_empty() && !predicates.contains(&false),
                _ => false,
            }
        }
        _ => name == "test",
    }
}

/// Returns whether an attribute, by the tokens within its brackets, sets the file of a module:
/// `#[path = "..."]`, directly or through `cfg_attr`.
fn sets_path(attribute: &[Token<'_>]) -> bool {
    match attribute.first().map(|token| plain(token.text)) {
        Some("path") => true,
        Some("cfg_attr") => attribute
            .windows(2)
            .any(|pair| plain(pair[0].text) == "path" && pair[1].text == "="),
        _ => false,
    }
}

/// Returns whether an attribute, by the tokens within its brackets, is or may be `name`, such as
/// `macro_export`: directly, or through `cfg_attr` under any predicate.
fn may_be(attribute: &[Token<'_>], name: &str) -> bool {
    match attribute.first().map(|token| plain(token.text)) {
        Some("cfg_attr") => attribute.iter().any(|token| plain(token.text) == name),
        Some(first) => first == name,
        None => false,
    }
}

/// Returns the `crate::`, `super::`, and `self::` paths that the attribute whose brackets open at
/// `tokens[open]` and close at `tokens[close]`, or at the end, writes, each with its segments and
/// the line of its last segment, in the order of their lines: those among its tokens, such as a
/// derive's, and those in its strings, with their escapes decoded, such as serde's `with = "..."`,
/// which a macro turns into code. The strings of documentation, such as `doc = "..."` or
/// `doc(alias = "...")`, also within a `cfg_attr`, name none, as a doc comment does not. `text` is
/// the text that blanking turned into the text of `tokens`.
fn attribute_paths(
    text: &str,
    tokens: &[Token<'_>],
    open: usize,
    close: usize,
) -> Vec<WrittenPath> {
    let mut paths = qualified_paths(&tokens[open + 1..close], |token| token.line);
    let documentation: Vec<Range<usize>> = (open + 1..close)
        .filter(|&index| plain(tokens[index].text) == "doc")
        .filter_map(|index| {
            let end = match text_at(tokens, index + 1) {
                "=" => scan(tokens, index + 2, false, |text| text == ",").unwrap_or_else(|end| end),
                "(" => group_end(tokens, index + 1)?,
                _ => return None,
            };
            Some(tokens[index].offset..tokens.get(end).map_or(text.len(), |token| token.offset))
        })
        .collect();
    let from = tokens[open].offset;
    let to = tokens.get(close).map_or(text.len(), |token| token.offset);
    let mut at = from;
    while at < to {
        let Some(end) = literal_end(text.as_bytes(), at) else {
            at += 1;
            continue;
        };
        let literal = &text[at..end];
        // A comment or a character literal holds no string.
        if !literal.starts_with('/')
            && !documentation.iter().any(|range| range.contains(&at))
            && let (Some(first), Some(last)) = (literal.find('"'), literal.rfind('"'))
            && first < last
        {
            let line = tokens[open].line + text[from..at].matches('\n').count();
            let body = &literal[first + 1..last];
            // A raw string, whose prefix has an `r`, has no escapes.
            let (decoded, lines) = if literal[..first].contains('r') {
                let lines = body
                    .bytes()
                    .scan(0, |feeds, byte| {
                        let before = *feeds;
                        *feeds += usize::from(byte == b'\n');
                        Some(before)
                    })
                    .collect();
                (body.to_owned(), lines)
            } else {
                unescape(body)
            };
            paths.extend(qualified_paths(&tokenize(&decoded), |token| {
                line + lines[token.offset]
            }));
        }
        at = end;
    }
    paths.sort_by_key(|&(_, line)| line);
    paths
}

/// Returns the text that `body`, the body of a string literal that is not raw, stands for, with
/// its escapes decoded, and, for each byte of that text, the number of line feeds in `body` before
/// the byte's source. A `\` that ends a line joins the line to the next one, past the whitespace
/// that starts it, as in Rust.
fn unescape(body: &str) -> (String, Vec<usize>) {
    let mut text = String::new();
    let mut lines = Vec::new();
    let mut line = 0;
    let mut characters = body.chars().peekable();
    while let Some(character) = characters.next() {
        let decoded = if character == '\\' {
            match characters.next() {
                Some('x') => {
                    let digits: String = characters.by_ref().take(2).collect();
                    u8::from_str_radix(&digits, 16).ok().map(char::from)
                }
                Some('u') => {
                    let digits: String = characters
                        .by_ref()
                        .skip(1)
                        .take_while(|&digit| digit != '}')
                        .filter(|&digit| digit != '_')
                        .collect();
                    u32::from_str_radix(&digits, 16)
                        .ok()
                        .and_then(char::from_u32)
                }
                Some('n') => Some('\n'),
                Some('r') => Some('\r'),
                Some('t') => Some('\t'),
                Some('0') => Some('\0'),
                Some(feed @ ('\n' | '\r')) => {
                    line += usize::from(feed == '\n');
                    while let Some(&next) = characters.peek()
                        && next.is_ascii_whitespace()
                    {
                        line += usize::from(next == '\n');
                        characters.next();
                    }
                    None
                }
                other => other,
            }
        } else {
            Some(character)
        };
        if let Some(decoded) = decoded {
            text.push(decoded);
            lines.resize(text.len(), line);
        }
        line += usize::from(character == '\n');
    }
    (text, lines)
}

/// Scans the region from `tokens[from]`, within whose own brackets only `stop` looks, outside the
/// angle brackets of generic arguments if `angles`. Returns `Ok` with the index of the first token
/// at the region's level that `stop` accepts, or `Err` with the index at which the region ends.
fn scan(
    tokens: &[Token<'_>],
    from: usize,
    angles: bool,
    stop: impl Fn(&str) -> bool,
) -> Result<usize, usize> {
    let mut depth = 0usize;
    let mut open = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(from) {
        if depth == 0 && open == 0 && stop(token.text) {
            return Ok(index);
        }
        match token.text {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" if depth == 0 => return Err(index),
            ")" | "]" | "}" => depth -= 1,
            "<" if angles && depth == 0 => open += 1,
            // The `>` of an arrow, as in `fn() -> T`, closes no angle bracket.
            ">" if angles && depth == 0 && text_at(tokens, index.wrapping_sub(1)) != "-" => {
                open = open.saturating_sub(1);
            }
            _ => {}
        }
    }
    Err(tokens.len())
}

/// Returns the index after the bracketed group that opens at `tokens[open]`, if it closes.
fn group_end(tokens: &[Token<'_>], open: usize) -> Option<usize> {
    scan(tokens, open + 1, false, |_| false)
        .err()
        .filter(|&close| close < tokens.len())
        .map(|close| close + 1)
}

/// Returns the index after the macro invocation whose bracketed arguments open at `tokens[open]`:
/// after their braces, or after the `;` that follows their parentheses or brackets.
fn macro_end(tokens: &[Token<'_>], open: usize) -> Option<usize> {
    let end = group_end(tokens, open)?;
    match text_at(tokens, open) {
        "{" => Some(end),
        "(" | "[" if text_at(tokens, end) == ";" => Some(end + 1),
        _ => None,
    }
}

/// Returns whether an expression with a block, which a match arm needs no comma after, starts at
/// `tokens[at]`: a block; a `const`, `unsafe`, or `async` block; a loop, labeled or not; a
/// `match`; or an `if`.
fn starts_block(tokens: &[Token<'_>], at: usize) -> bool {
    let (first, second) = (text_at(tokens, at), text_at(tokens, at + 1));
    // A label, as in `'outer: loop`, or a block, as in `async move {` but not the async closure of
    // `async move ||`.
    (first.starts_with('\'') && second == ":")
        || matches!(first, "{" | "if" | "match" | "while" | "for" | "loop")
        || (matches!(first, "const" | "unsafe" | "async") && second == "{")
        || (first == "async" && second == "move" && text_at(tokens, at + 2) == "{")
}

/// Returns the index after the expression with a block that starts at `tokens[at]`: after the
/// first block at its own level, or after the blocks of the `else` branches that follow that
/// block. The first block may be the condition of an `if`, in which case the expression's block
/// is left out, but never more than the expression.
fn block_end(tokens: &[Token<'_>], at: usize) -> Option<usize> {
    let mut from = at;
    loop {
        let open = scan(tokens, from, false, |text| matches!(text, "{" | ";")).ok()?;
        if text_at(tokens, open) != "{" {
            return None;
        }
        let end = group_end(tokens, open)?;
        if text_at(tokens, end) != "else" {
            return Some(end);
        }
        from = end + 1;
    }
}

/// The tokens that start an item, or the attribute before one, which neither the header of an
/// item nor an expression statement holds at its own level: a scan of either that meets one has
/// run past it, as through an item that the test does not know.
const ITEM_STARTS: [&str; 11] = [
    "#",
    "pub",
    "struct",
    "enum",
    "trait",
    "mod",
    "use",
    "let",
    "static",
    "type",
    "macro_rules",
];

/// Returns the index after the code that starts at `tokens[at]`, in a region that holds `list`,
/// if its tokens tell where it ends: a field, parameter, variant, or arm of such a list; an item;
/// a statement that ends with a `;`; a macro invocation; or a block, `if`, `match`, or loop, with
/// the blocks of the `else` branches of an `if`. `None` for anything else, such as a field of a
/// struct expression, whose references then count as production code: the test never takes code
/// for test-only beyond where it can tell that the test-only code ends.
fn extent(tokens: &[Token<'_>], at: usize, list: List) -> Option<usize> {
    let start = after_visibility(tokens, at);
    // The end of an element of a list: its comma, or the end of the list. An attribute or a
    // visibility starts the next element, so the scan has run past this one.
    let element = |from, angles| match scan(tokens, from, angles, |text| {
        matches!(text, "," | "#" | "pub")
    }) {
        Ok(end) => (text_at(tokens, end) == ",").then_some(end),
        Err(end) => Some(end),
    };
    match list {
        List::Fields => return element(start, true),
        List::Variants => return element(start, false),
        List::Arms => {
            // An arm whose expression has a block may end without a comma; any other ends with
            // one, unless it is the last arm.
            let arrow = scan(tokens, start, false, |text| matches!(text, "=>" | "#")).ok()?;
            let body = (text_at(tokens, arrow) == "=>").then_some(arrow + 1)?;
            if !starts_block(tokens, body) {
                return element(body, false);
            }
            let end = block_end(tokens, body)?;
            return Some(end + usize::from(text_at(tokens, end) == ","));
        }
        List::Code => {}
    }
    let mut at = start;
    while matches!(
        (text_at(tokens, at), text_at(tokens, at + 1)),
        (
            "default" | "async" | "unsafe" | "const" | "extern",
            "fn" | "unsafe" | "async" | "extern" | "impl" | "trait"
        )
    ) {
        at += 1;
    }
    // The body of an item, past the angle brackets of its generics, or the `;` that ends an item
    // without one.
    let item = || {
        let stop = scan(tokens, at + 1, true, |text| {
            matches!(text, ";" | "{" | "=" | "const") || ITEM_STARTS.contains(&text)
        })
        .ok()?;
        match text_at(tokens, stop) {
            ";" => Some(stop + 1),
            "{" => group_end(tokens, stop),
            _ => None,
        }
    };
    match (text_at(tokens, at), text_at(tokens, at + 1)) {
        _ if starts_block(tokens, at) => block_end(tokens, at),
        ("use" | "const" | "static" | "type" | "let", _) | ("extern", "crate") => {
            scan(tokens, at, false, |text| text == ";")
                .ok()
                .map(|end| end + 1)
        }
        ("fn" | "impl" | "trait" | "struct" | "enum" | "extern" | "mod", _) => item(),
        ("union", name) if is_identifier(name) => item(),
        ("macro_rules", "!") => macro_end(tokens, at + 3),
        _ => {
            let mut path = at;
            while is_identifier(text_at(tokens, path))
                || matches!(text_at(tokens, path), "::" | "$")
            {
                path += 1;
            }
            if path > at
                && text_at(tokens, path) == "!"
                && let Some(end) = macro_end(tokens, path + 1)
            {
                return Some(end);
            }
            // An expression statement, unless a `,` or `=>` shows that the code is no statement,
            // or the scan runs into an item.
            let end = scan(tokens, at, false, |text| {
                matches!(
                    text,
                    ";" | "," | "=>" | "fn" | "impl" | "const" | "extern" | "union" | "macro"
                ) || ITEM_STARTS.contains(&text)
            })
            .ok()?;
            (text_at(tokens, end) == ";").then_some(end + 1)
        }
    }
}

/// Returns what the brackets that open lists hold, by their indices in `tokens`: the fields of the
/// structs and unions and the parameters of the functions that `tokens` declare, the variants of
/// their enums, and the arms of their `match` expressions. The fields of a variant, which open
/// after its name within the variants, are not among them.
fn lists(tokens: &[Token<'_>]) -> BTreeMap<usize, List> {
    let mut lists = BTreeMap::new();
    for (index, token) in tokens.iter().enumerate() {
        let declares = is_identifier(text_at(tokens, index + 1));
        let open = match token.text {
            "struct" | "union" | "enum" | "fn" if declares => {
                scan(tokens, index + 2, true, |text| {
                    matches!(text, "(" | "{" | ";")
                })
            }
            "match" => scan(tokens, index + 1, false, |text| matches!(text, "{" | ";")),
            _ => continue,
        };
        let Ok(open) = open else {
            continue;
        };
        let list = match (token.text, text_at(tokens, open)) {
            ("struct" | "union", "(" | "{") | ("fn", "(") => List::Fields,
            ("enum", "{") => List::Variants,
            ("match", "{") => List::Arms,
            _ => continue,
        };
        lists.insert(open, list);
    }
    lists
}

/// Expands the `use` tree at `tokens[*at]`, beneath `prefix`, into `imports`, each with its
/// segments, kind, and line, and moves `*at` past the tree.
fn expand(
    tokens: &[Token<'_>],
    at: &mut usize,
    prefix: &[String],
    imports: &mut Vec<(Vec<String>, Kind, usize)>,
) {
    let mut segments = prefix.to_vec();
    while let Some(token) = tokens.get(*at) {
        match token.text {
            "::" => *at += 1,
            "*" => {
                *at += 1;
                imports.push((segments, Kind::Glob, token.line));
                return;
            }
            "{" => {
                *at += 1;
                while !matches!(text_at(tokens, *at), "}" | "") {
                    if text_at(tokens, *at) == "," {
                        *at += 1;
                        continue;
                    }
                    let before = *at;
                    expand(tokens, at, &segments, imports);
                    if *at == before {
                        *at += 1;
                    }
                }
                *at += 1;
                return;
            }
            text if is_identifier(text) => {
                *at += 1;
                // In a list, `self` names the module that the list is in.
                if text != "self" || segments.is_empty() {
                    segments.push(unraw(text));
                }
                if text_at(tokens, *at) == "::" {
                    continue;
                }
                let mut imported = segments.last().cloned();
                if text_at(tokens, *at) == "as" {
                    imported = Some(unraw(text_at(tokens, *at + 1))).filter(|alias| alias != "_");
                    *at += 2;
                }
                imports.push((segments, Kind::Import(imported), token.line));
                return;
            }
            _ => return,
        }
    }
}

/// Finds the declarations, inline modules, references, and `#[path]` attributes of the file of
/// `module`, whose text is `text`.
fn parse(module: &[String], text: &str) -> Facts {
    let blanked = blank(text);
    let tokens = tokenize(&blanked);
    let lists = lists(&tokens);
    let mut facts = Facts::default();
    let mut frames: Vec<Frame> = Vec::new();
    let mut file_test = false;
    // The index of the token after the test-only code that the parser is in, if it is in any.
    let mut test_until = 0;
    let mut attributes_test = false;
    // The index of the first of the attributes that the parser is past, if it is past any.
    let mut attributes_from = None;
    // The paths of the attributes that the parser is past, each with whether its attribute is an
    // inner one, `#![...]`, which applies to the region that it is in, rather than to what follows.
    let mut pending_paths: Vec<(bool, Vec<WrittenPath>)> = Vec::new();
    let mut macro_export = false;
    let mut path_attribute = None;
    let mut body_module = None;
    let mut at = 0;
    while at < tokens.len() {
        let token = tokens[at];
        if token.text == "#"
            && let Some((end, inner, inside)) = attribute(&tokens, at)
        {
            attributes_from.get_or_insert(at);
            let open = at + 1 + usize::from(inner);
            pending_paths.push((
                inner,
                attribute_paths(text, &tokens, open, open + 1 + inside.len()),
            ));
            if sets_path(inside) {
                path_attribute = Some(token.line);
            }
            if may_be(inside, "macro_use") {
                let mut scope = module.to_vec();
                scope.extend(frames.iter().filter_map(|frame| frame.module.clone()));
                facts.macro_uses.push((scope, token.line));
            }
            macro_export |= may_be(inside, "macro_export");
            if guards_test(inside) {
                match (inner, frames.last_mut()) {
                    (false, _) => attributes_test = true,
                    (true, Some(frame)) => frame.test = true,
                    (true, None) => file_test = true,
                }
            }
            at = end;
            continue;
        }
        if let Some(line) = path_attribute.take() {
            let start = after_visibility(&tokens, at);
            let placed =
                (text_at(&tokens, start) == "mod").then(|| unraw(text_at(&tokens, start + 1)));
            let mut scope = module.to_vec();
            scope.extend(frames.iter().filter_map(|frame| frame.module.clone()));
            facts.path_attributes.push((scope, line, placed));
        }
        // Where the region holds code, only the start of the file or a `{`, `}`, or `;` before the
        // attributes shows that an item or a statement starts after them. Anything else, such as
        // the `<`, `|`, or `,` before a parameter of generics or of a closure, starts an element
        // of a list that the test does not know.
        let starts_statement = attributes_from.take().is_some_and(|first: usize| {
            matches!(
                text_at(&tokens, first.wrapping_sub(1)),
                "" | "{" | "}" | ";"
            )
        });
        // Whether the region is test-only, as its inner attributes are.
        let region = file_test || at < test_until || frames.last().is_some_and(|frame| frame.test);
        if std::mem::take(&mut attributes_test) {
            let list = frames.last().map_or(List::Code, |frame| frame.list);
            if (list != List::Code || starts_statement)
                && let Some(end) = extent(&tokens, at, list)
            {
                test_until = test_until.max(end);
            }
        }
        let test = region || at < test_until;
        let local = frames.iter().any(|frame| frame.module.is_none());
        let exported = std::mem::take(&mut macro_export);
        let current = || {
            let mut current = module.to_vec();
            current.extend(frames.iter().filter_map(|frame| frame.module.clone()));
            current
        };
        // An outer attribute is test-only where what it applies to is.
        for (inner, paths) in pending_paths.drain(..) {
            facts.add_paths(&current(), paths, if inner { region } else { test }, local);
        }
        if let Some((segments, last, end)) = qualified_path(&tokens, at) {
            facts.add_paths(&current(), vec![(segments, tokens[last].line)], test, local);
            at = end;
            continue;
        }
        match token.text {
            // `#[macro_export]` puts the macro at the crate root, as `crate::NAME!`.
            "macro_rules" if exported && text_at(&tokens, at + 1) == "!" => {
                facts
                    .exported
                    .push((current(), unraw(text_at(&tokens, at + 2)), test));
            }
            "use" if text_at(&tokens, at + 1) != "<" => {
                let mut end = at + 1;
                let mut imports = Vec::new();
                expand(&tokens, &mut end, &[], &mut imports);
                for (segments, kind, line) in imports {
                    facts.references.push(Reference {
                        module: current(),
                        segments,
                        kind,
                        line,
                        test,
                        local,
                    });
                }
                // The `;` that ends the declaration is next.
                at = end.max(at + 1);
                continue;
            }
            "mod" if is_identifier(text_at(&tokens, at + 1)) => {
                let declared_name = unraw(text_at(&tokens, at + 1));
                match text_at(&tokens, at + 2) {
                    ";" => {
                        let mut declared = current();
                        declared.push(declared_name);
                        facts.declared.push((declared, test));
                    }
                    "{" => body_module = Some(declared_name),
                    _ => {}
                }
            }
            // `extern crate self as NAME;` imports the crate root under another name.
            "extern"
                if text_at(&tokens, at + 1) == "crate" && text_at(&tokens, at + 2) == "self" =>
            {
                let name = (text_at(&tokens, at + 3) == "as")
                    .then(|| unraw(text_at(&tokens, at + 4)))
                    .filter(|alias| alias != "_");
                facts.references.push(Reference {
                    module: current(),
                    segments: vec!["crate".to_owned()],
                    kind: Kind::Import(name),
                    line: token.line,
                    test,
                    local,
                });
            }
            "{" | "(" | "[" => {
                let name = if token.text == "{" {
                    body_module.take()
                } else {
                    None
                };
                if let Some(name) = &name {
                    let mut inline = current();
                    inline.push(name.clone());
                    facts.inline.push(inline);
                }
                // The fields of a variant follow its name, which starts the variant, among the
                // variants of an enum, unlike the brackets of an expression that sets a
                // discriminant.
                let list = match lists.get(&at) {
                    Some(&list) => list,
                    None if token.text != "["
                        && frames
                            .last()
                            .is_some_and(|frame| frame.list == List::Variants)
                        && is_identifier(text_at(&tokens, at.wrapping_sub(1)))
                        && matches!(text_at(&tokens, at.wrapping_sub(2)), "{" | "," | "]") =>
                    {
                        List::Fields
                    }
                    None => List::Code,
                };
                frames.push(Frame {
                    test: test || name.as_deref() == Some("tests"),
                    module: name,
                    list,
                });
            }
            "}" | ")" | "]" => {
                frames.pop();
            }
            _ => {}
        }
        at += 1;
    }
    // Attributes that nothing follows, such as the inner attributes of a file without items.
    let mut scope = module.to_vec();
    scope.extend(frames.iter().filter_map(|frame| frame.module.clone()));
    let region = file_test || frames.last().is_some_and(|frame| frame.test);
    let local = frames.iter().any(|frame| frame.module.is_none());
    for (_, paths) in pending_paths {
        facts.add_paths(&scope, paths, region, local);
    }
    facts
}

/// Returns the module of the file at `path` in the crate, such as `["host", "store"]` for
/// `src/host/store/mod.rs`, or `None` for a path that is not a source file.
fn module_of(path: &str) -> Option<Vec<String>> {
    let relative = path.strip_prefix("src/")?.strip_suffix(".rs")?;
    let mut module: Vec<String> = relative.split('/').map(str::to_owned).collect();
    if module == ["lib"] || module.last().is_some_and(|last| last == "mod") {
        module.pop();
    }
    Some(module)
}

/// Returns whether the file of `module` holds test-only code alone: whether every declaration of
/// it is test-only, or is in a file that holds test-only code alone. `declarations` holds, for
/// each module that a `mod NAME;` declaration places in a file, the module of each file that
/// declares it and whether the declaration is test-only.
fn file_is_test(
    module: &[String],
    declarations: &BTreeMap<Vec<String>, Vec<(Vec<String>, bool)>>,
) -> bool {
    match declarations.get(module) {
        Some(declared) => declared
            .iter()
            .all(|(parent, test)| *test || file_is_test(parent, declarations)),
        // The crate root, which no file declares.
        None => false,
    }
}

/// Builds the dependencies between the direct children of `host` from `sources`, which hold
/// `src/lib.rs` and the files of `src/host/`, or fails if their modules cannot be followed.
fn analyze(sources: &[Source]) -> Result<Graph, String> {
    let mut sources: Vec<&Source> = sources.iter().collect();
    sources.sort_by(|one, other| one.path.cmp(&other.path));
    let mut files = Vec::new();
    let mut modules = Modules::default();
    let mut declarations: BTreeMap<Vec<String>, Vec<(Vec<String>, bool)>> = BTreeMap::new();
    for source in sources {
        let module = module_of(&source.path)
            .ok_or_else(|| format!("{} is not a source file of the crate", source.path))?;
        let facts = parse(&module, &source.text);
        let in_host = |scope: &[String]| scope.first().is_some_and(|first| first == "host");
        for (scope, line, placed) in &facts.path_attributes {
            if in_host(scope) || (scope.is_empty() && placed.as_deref() == Some("host")) {
                return Err(format!(
                    "{}:{line} places a module in a file with #[path], which this test cannot \
                     follow: let the module's file be the one that its name implies",
                    source.path
                ));
            }
        }
        if let Some((_, line)) = facts.macro_uses.iter().find(|(scope, _)| in_host(scope)) {
            return Err(format!(
                "{}:{line} brings macros into scope with #[macro_use], whose uses name no path \
                 that this test can follow: import each macro by its path instead",
                source.path
            ));
        }
        modules.paths.insert(module.clone());
        modules.paths.extend(facts.inline.iter().cloned());
        for (declared, test) in &facts.declared {
            modules.paths.insert(declared.clone());
            declarations
                .entry(declared.clone())
                .or_default()
                .push((module.clone(), *test));
        }
        files.push((source, module, facts));
    }
    for (source, module, _) in &files {
        if !module.is_empty() && !declarations.contains_key(module) {
            return Err(format!(
                "no `mod` declaration names {}, so the crate does not build it: declare it or \
                 delete it",
                source.path
            ));
        }
    }
    let production = |module: &Vec<String>, reference: &Reference| {
        !reference.test && !file_is_test(module, &declarations)
    };
    // The macros that the children of `host` export at the crate root, as `crate::NAME!`, each
    // from the module, maybe an inline one, that defines it.
    for (_, module, facts) in &files {
        if file_is_test(module, &declarations) {
            continue;
        }
        for (scope, name, _) in facts.exported.iter().filter(|(_, _, test)| !test) {
            if let [host, child, ..] = scope.as_slice()
                && host == "host"
            {
                modules
                    .imports
                    .entry((Vec::new(), format!("{name}!")))
                    .or_default()
                    .insert(child.clone());
            }
        }
    }
    // The names that the crate root and `host` import from the children of `host`, such as
    // `crate::Artifacts`. An import may name what another one imports, in either of them and in
    // either order, or what its own module imports by the name alone, so the imports are read
    // again until they name no child that they did not.
    loop {
        let mut grew = false;
        for (source, module, facts) in &files {
            for reference in &facts.references {
                let scope = reference.module.as_slice();
                if !(scope.is_empty() || scope == ["host"])
                    || reference.kind == Kind::Path
                    || reference.local
                    || !production(module, reference)
                {
                    continue;
                }
                let Some(path) = modules.absolute(scope, &reference.segments, true) else {
                    continue;
                };
                match &reference.kind {
                    // An import takes its name in each namespace that has it, a macro's too.
                    Kind::Import(Some(name)) => {
                        for (named, imported) in [
                            (path.clone(), name.clone()),
                            (as_macro(&path), format!("{name}!")),
                        ] {
                            let Target::Children(children) = modules.target(&named) else {
                                continue;
                            };
                            let known = modules
                                .imports
                                .entry((scope.to_vec(), imported))
                                .or_default();
                            let before = known.len();
                            known.extend(children);
                            grew |= known.len() > before;
                        }
                    }
                    Kind::Glob if matches!(modules.target(&path), Target::Children(_)) => {
                        return Err(format!(
                            "{}:{} imports everything of {} into {}, so this test cannot tell \
                             which child of host a path through it names: import the items by \
                             name",
                            source.path,
                            reference.line,
                            reference.segments.join("::"),
                            if scope.is_empty() {
                                "the crate root"
                            } else {
                                "host"
                            },
                        ));
                    }
                    Kind::Glob | Kind::Import(None) | Kind::Path => {}
                }
            }
        }
        if !grew {
            break;
        }
    }
    let mut graph = Graph::default();
    for (source, module, facts) in &files {
        for reference in &facts.references {
            if !production(module, reference) {
                continue;
            }
            let import = reference.kind != Kind::Path;
            let Some(path) = modules.absolute(&reference.module, &reference.segments, import)
            else {
                continue;
            };
            // An import takes its name in each namespace that has it, a macro's too.
            let target = match (
                modules.target(&path),
                import.then(|| modules.target(&as_macro(&path))),
            ) {
                (Target::Children(mut children), Some(Target::Children(macros))) => {
                    children.extend(macros);
                    Target::Children(children)
                }
                (Target::Outside, Some(Target::Children(macros))) => Target::Children(macros),
                (target, _) => target,
            };
            let location = format!("{}:{}", source.path, reference.line);
            if import && matches!(target, Target::Root | Target::Host) {
                return Err(format!(
                    "{location} imports {} itself, which hides the children of host that the \
                     code that uses it depends on: import what it uses from those children",
                    if target == Target::Root {
                        "the crate root"
                    } else {
                        "host"
                    }
                ));
            }
            let (Target::Children(children), [host, from, ..]) =
                (target, reference.module.as_slice())
            else {
                continue;
            };
            if host != "host" {
                continue;
            }
            let mut written = reference.segments.join("::");
            if reference.kind == Kind::Glob {
                written.push_str("::*");
            }
            for to in children.into_iter().filter(|to| to != from) {
                graph
                    .edges
                    .entry((from.clone(), to))
                    .or_insert_with(|| Example {
                        location: location.clone(),
                        path: written.clone(),
                    });
            }
        }
    }
    Ok(graph)
}

/// Returns the cycles of `edges`: their strongly connected components that hold more than one
/// child, each in the order of its children's names, and in the order of their first children.
fn cycles(edges: &BTreeMap<(String, String), Example>) -> Vec<Vec<String>> {
    let mut successors: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (from, to) in edges.keys() {
        successors.entry(from).or_default().push(to);
        successors.entry(to).or_default();
    }
    let mut search = Search {
        successors: &successors,
        order: BTreeMap::new(),
        low: BTreeMap::new(),
        stack: Vec::new(),
        components: Vec::new(),
    };
    for &child in successors.keys() {
        if !search.order.contains_key(child) {
            search.visit(child);
        }
    }
    let mut cycles: Vec<Vec<String>> = search
        .components
        .into_iter()
        .filter(|component| component.len() > 1)
        .map(|mut component| {
            component.sort_unstable();
            component.into_iter().map(str::to_owned).collect()
        })
        .collect();
    cycles.sort();
    cycles
}

/// Tarjan's search for the strongly connected components of a graph.
struct Search<'a> {
    /// The successors of each node.
    successors: &'a BTreeMap<&'a str, Vec<&'a str>>,
    /// The order in which the search reached each node that it reached.
    order: BTreeMap<&'a str, usize>,
    /// The lowest order of the nodes that each reached node reaches through nodes on the stack.
    low: BTreeMap<&'a str, usize>,
    /// The reached nodes whose components are not complete yet.
    stack: Vec<&'a str>,
    /// The complete components.
    components: Vec<Vec<&'a str>>,
}

impl<'a> Search<'a> {
    /// Reaches `node`, which the search has not reached yet, and the nodes that it reaches.
    fn visit(&mut self, node: &'a str) {
        let order = self.order.len();
        self.order.insert(node, order);
        self.low.insert(node, order);
        self.stack.push(node);
        let successors = self.successors;
        for &next in &successors[node] {
            if !self.order.contains_key(next) {
                self.visit(next);
                let low = self.low[node].min(self.low[next]);
                self.low.insert(node, low);
            } else if self.stack.contains(&next) {
                let low = self.low[node].min(self.order[next]);
                self.low.insert(node, low);
            }
        }
        if self.low[node] == order {
            let start = self.stack.iter().rposition(|&on| on == node).unwrap();
            let component = self.stack.split_off(start);
            self.components.push(component);
        }
    }
}

/// Describes `cycles`, the cycles of `graph`, with one reference for each dependency within
/// them, and how to break them.
fn report(graph: &Graph, cycles: &[Vec<String>]) -> String {
    let mut text = String::from(
        "the direct children of nvx::host must depend on one another without cycles, but these \
         do, through the references shown:\n",
    );
    for cycle in cycles {
        writeln!(text, "\n{}:", cycle.join(", ")).unwrap();
        for ((from, to), example) in &graph.edges {
            if cycle.contains(from) && cycle.contains(to) {
                writeln!(
                    text,
                    "  {from} -> {to}: {} uses {}",
                    example.location, example.path
                )
                .unwrap();
            }
        }
    }
    text.push_str(
        "\nTo break a cycle, move the item that a lower child takes from a higher one into the \
         lower child, or into a new child beneath both, and re-export it at its old public path, \
         so that the public API stays the same.\n",
    );
    text
}

/// Returns the sources of a crate whose files are `files`, by their paths and texts.
fn crate_of(files: &[(&str, &str)]) -> Vec<Source> {
    files
        .iter()
        .map(|&(path, text)| Source {
            path: path.to_owned(),
            text: text.to_owned(),
        })
        .collect()
}

/// Returns the dependencies of the crate whose files are `files`, as `FROM -> TO`.
fn dependencies(files: &[(&str, &str)]) -> Vec<String> {
    let graph = analyze(&crate_of(files)).unwrap_or_else(|error| panic!("{error}"));
    graph
        .edges
        .keys()
        .map(|(from, to)| format!("{from} -> {to}"))
        .collect()
}

/// Returns the dependencies of the crate whose files are `files`, as `FROM -> TO at FILE:LINE`,
/// with the first reference that makes each.
fn located_dependencies(files: &[(&str, &str)]) -> Vec<String> {
    let graph = analyze(&crate_of(files)).unwrap_or_else(|error| panic!("{error}"));
    graph
        .edges
        .iter()
        .map(|((from, to), example)| format!("{from} -> {to} at {}", example.location))
        .collect()
}

/// Returns the tokens that remain of `text` once it is blanked, separated by spaces, after
/// checking that blanking kept the length and the lines of `text`.
fn remains(text: &str) -> String {
    let blanked = blank(text);
    assert_eq!(blanked.len(), text.len(), "{text}");
    assert!(
        blanked
            .bytes()
            .zip(text.bytes())
            .all(|(kept, original)| (kept == b'\n') == (original == b'\n')),
        "{text}"
    );
    let tokens: Vec<&str> = tokenize(&blanked).iter().map(|token| token.text).collect();
    tokens.join(" ")
}

/// Returns the paths that the `use` declarations in `text` import, written as
/// `PATH as NAME`, `PATH as _`, or `PATH::*` for a glob.
fn imports(text: &str) -> Vec<String> {
    let module = ["host".to_owned(), "a".to_owned()];
    parse(&module, text)
        .references
        .iter()
        .map(|reference| {
            let path = reference.segments.join("::");
            match &reference.kind {
                Kind::Import(Some(name)) => format!("{path} as {name}"),
                Kind::Import(None) => format!("{path} as _"),
                Kind::Glob => format!("{path}::*"),
                Kind::Path => format!("{path} (not imported)"),
            }
        })
        .collect()
}

#[test]
fn the_children_of_host_depend_on_one_another_without_cycles() {
    let graph = analyze(&read_sources()).unwrap_or_else(|error| panic!("{error}"));
    let cycles = cycles(&graph.edges);
    assert!(cycles.is_empty(), "{}", report(&graph, &cycles));
}

#[test]
fn the_graph_holds_well_known_dependencies_of_the_sources() {
    let graph = analyze(&read_sources()).unwrap_or_else(|error| panic!("{error}"));
    for (from, to) in [
        ("instance", "store"),
        ("supervisor", "store"),
        ("cli", "sandbox"),
        ("store", "spawn"),
    ] {
        assert!(
            graph.edges.contains_key(&(from.to_owned(), to.to_owned())),
            "the graph lacks {from} -> {to}"
        );
    }
}

#[test]
fn blanking_keeps_code_and_lines_but_not_comments_or_literals() {
    assert_eq!(remains("a // crate::x\nb"), "a b");
    assert_eq!(remains("a /// crate::x\n//! crate::y\nb"), "a b");
    assert_eq!(remains("a /** crate::x */ b"), "a b");
    assert_eq!(remains("a /* x /* crate::y */ crate::z */ b"), "a b");
    assert_eq!(remains(r#"a "x \" crate::y \\" b"#), "a b");
    assert_eq!(remains("a \"x\ncrate::y\n\" b"), "a b");
    assert_eq!(remains(r#"a b"crate::x" c"crate::y" b"#), "a b");
    assert_eq!(remains(r#"a r"x\" b"#), "a b");
    assert_eq!(remains(r##"a r#"x "crate::y" z"# b"##), "a b");
    assert_eq!(remains(r###"a r##"x "# crate::y"## b"###), "a b");
    assert_eq!(remains(r##"a br#"crate::x"# cr"crate::y" b"##), "a b");
    assert_eq!(
        remains(r#"a '"' crate::y '\'' '\\' '\u{1F600}' 'é' b'"' b'\'' b"#),
        "a crate :: y b"
    );
    assert_eq!(
        remains("fn f<'a>(x: &'a str) { 'outer: loop { break 'outer; } crate::y }"),
        "fn f < 'a > ( x : & 'a str ) { 'outer : loop { break 'outer ; } crate :: y }"
    );
    assert_eq!(remains("r#type crate::y"), "r#type crate :: y");
    assert_eq!(
        remains("crate::x(br, b, r) b'x'"),
        "crate :: x ( br , b , r )"
    );
}

#[test]
fn use_trees_expand_into_the_paths_that_they_import() {
    assert_eq!(
        imports(
            "pub(crate) use crate::host::{\n    self,\n    b::{One, two as three},\n    c::*,\n    \
             d::{self as e, f::{self}},\n    g::G as _,\n};"
        ),
        [
            "crate::host as host",
            "crate::host::b::One as One",
            "crate::host::b::two as three",
            "crate::host::c::*",
            "crate::host::d as e",
            "crate::host::d::f as f",
            "crate::host::g::G as _",
        ]
    );
    assert_eq!(
        imports("use ::std::fmt;\nuse super::super::x::Y;\nuse self::z;"),
        ["std::fmt as fmt", "super::super::x::Y as Y", "self::z as z"]
    );
    // Precise capturing, `use<'a>`, imports nothing.
    assert_eq!(
        imports("fn f<'a>() -> impl Sized + use<'a> { crate::x::y() }"),
        ["crate::x::y (not imported)"]
    );
    let lines: Vec<usize> = parse(&[], "use crate::{\n    a,\n    b::c,\n};")
        .references
        .iter()
        .map(|reference| reference.line)
        .collect();
    assert_eq!(lines, [2, 3]);
}

#[test]
fn test_only_code_is_not_a_dependency() {
    let a = r#"
#[cfg(test)]
use crate::host::b::One;
#[cfg(all(test, unix))]
pub(crate) fn helper<T, U>() -> T where T: Default, U: Default { crate::host::b::two() }
#[cfg(not(test))]
use crate::host::c::Three;
#[cfg(any(test, feature = "cli"))]
use crate::host::d::Four;
#[cfg(any(test, all(test, unix)))]
use crate::host::b::Five;
#[test]
fn check() { crate::host::b::six(); }
mod tests { use crate::host::b::Seven; }
#[cfg(test)]
impl Item { fn new() -> Self { crate::host::b::eight() } }
#[cfg(test)]
static TABLE: Map<u8, u8> = crate::host::b::NINE;
static OTHER: u8 = crate::host::e::TEN;
#[cfg(test)]
mod helpers;
fn production(value: u8) -> u8 {
    #[cfg(test)]
    crate::host::b::eleven();
    #[cfg(test)]
    if value == 0 {
        crate::host::b::twenty_six();
    } else if value == 1 {
        crate::host::b::twenty_seven();
    } else {
        crate::host::b::twenty_eight();
    }
    crate::host::j::twenty_nine();
    match value {
        #[cfg(test)]
        0 => { crate::host::b::twelve() }
        #[cfg(test)]
        1 => loop { crate::host::b::thirty_three(); }
        #[cfg(test)]
        2 => async move || crate::host::b::thirty_five(),
        3 => { crate::host::l::thirty_six(); }
        _ => crate::host::f::thirteen(),
    }
}
struct Fields {
    #[cfg(test)]
    value: Result<crate::host::b::Eighteen, crate::host::b::Nineteen>,
    #[cfg(test)]
    callback: fn(u8) -> Result<crate::host::b::Twenty, Vec<crate::host::b::TwentyOne>>,
    other: crate::host::i::TwentyTwo,
}
fn parameters(
    #[cfg(test)] value: Map<crate::host::b::TwentyThree, crate::host::b::TwentyFour>,
    other: crate::host::i::TwentyFive,
) {}
pub struct Tuple(
    #[cfg(test)] Result<crate::host::b::TwentySix, crate::host::b::TwentySeven>,
    crate::host::k::TwentyEight,
);
#[cfg(test)]
crate::make_tests! { crate::host::b::twenty_nine() }
pub fn after_a_macro() {
    crate::host::k::thirty();
}
#[cfg(test)]
fn bounded<T: Bound<{ 1 }>>() {
    crate::host::b::thirty_one();
}
pub fn after_a_bound() {
    crate::host::k::thirty_two();
}
#[cfg(test)]
fn label() -> &'static str {
    crate::host::b::thirty_four()
}
"#;
    assert_eq!(
        dependencies(&[
            ("src/lib.rs", "pub mod host;"),
            (
                "src/host/mod.rs",
                "pub mod a;\npub mod b;\npub mod c;\npub mod d;\npub mod e;\npub mod f;\n\
                 pub mod g;\n#[cfg(test)]\nmod h;\npub mod i;\npub mod j;\npub mod k;\npub mod l;"
            ),
            ("src/host/a.rs", a),
            ("src/host/a/helpers.rs", "use crate::host::b::Fourteen;"),
            ("src/host/b.rs", ""),
            ("src/host/c.rs", ""),
            ("src/host/d.rs", ""),
            ("src/host/e.rs", ""),
            ("src/host/f.rs", ""),
            (
                "src/host/g.rs",
                "#![cfg(test)]\nuse crate::host::b::Fifteen;"
            ),
            ("src/host/h.rs", "use crate::host::b::Sixteen;\nmod nested;"),
            ("src/host/h/nested.rs", "use crate::host::b::Seventeen;"),
            ("src/host/i.rs", ""),
            ("src/host/j.rs", ""),
            ("src/host/k.rs", ""),
            ("src/host/l.rs", ""),
        ]),
        [
            "a -> c", "a -> d", "a -> e", "a -> f", "a -> i", "a -> j", "a -> k", "a -> l"
        ]
    );
}

#[test]
fn guarded_code_whose_end_the_tokens_do_not_show_counts() {
    // The tokens do not show where a guarded field of a struct expression ends, since a `<` in it
    // may compare or open generic arguments, also where an expression sets a discriminant, nor
    // where a guarded `if` whose condition is a block does, nor where an item of a kind that the
    // test does not know does, short of the next item, nor where a guarded parameter of a closure
    // does, nor what a `cfg` that no item or statement follows guards: their references count.
    let a = r#"
fn build() -> Data {
    #[cfg(test)]
    if { true } {
        crate::host::b::one();
    }
    Data {
        #[cfg(test)]
        debug: crate::host::c::two() < 2,
        value: crate::host::d::three(),
    }
}
enum Kind {
    A = Data {
        #[cfg(test)]
        debug: 1 < 2,
        value: crate::host::e::FOUR,
    }
    .value,
    B = pick(#[cfg(test)] 1 < 2, crate::host::f::FIVE),
}
#[cfg(test)]
auto trait Marker {}
pub fn after_a_marker() {
    crate::host::g::six();
}
const AFTER: u8 = 1;
fn generic<#[cfg(test)] 'a, T>() {
    crate::host::h::seven();
}
fn constant<#[cfg(test)] const N: usize, T>() {}
use crate::host::i::Eight;
fn closure() {
    let callback = |#[cfg(test)] unused: ()| {
        crate::host::j::nine();
    };
}
cfg_if::cfg_if! {
    if #[cfg(test)] {
        use crate::host::b::Ten;
    } else {
        use crate::host::k::Eleven;
    }
}
"#;
    assert_eq!(
        dependencies(&[
            ("src/lib.rs", "pub mod host;"),
            (
                "src/host/mod.rs",
                "pub mod a;\npub mod b;\npub mod c;\npub mod d;\npub mod e;\npub mod f;\n\
                 pub mod g;\npub mod h;\npub mod i;\npub mod j;\npub mod k;"
            ),
            ("src/host/a.rs", a),
            ("src/host/b.rs", ""),
            ("src/host/c.rs", ""),
            ("src/host/d.rs", ""),
            ("src/host/e.rs", ""),
            ("src/host/f.rs", ""),
            ("src/host/g.rs", ""),
            ("src/host/h.rs", ""),
            ("src/host/i.rs", ""),
            ("src/host/j.rs", ""),
            ("src/host/k.rs", ""),
        ]),
        [
            "a -> b", "a -> c", "a -> d", "a -> e", "a -> f", "a -> g", "a -> h", "a -> i",
            "a -> j", "a -> k"
        ]
    );
}

#[test]
fn paths_in_attributes_count_where_what_the_attributes_apply_to_does() {
    // A derive that names a trait which `b` re-exports, while `b` uses the type that derives it,
    // makes a cycle.
    let graph = analyze(&crate_of(&[
        ("src/lib.rs", "pub mod host;"),
        ("src/host/mod.rs", "pub mod a;\npub mod b;"),
        (
            "src/host/a.rs",
            "#[derive(Debug, crate::host::b::Serialize)]\npub struct A;",
        ),
        (
            "src/host/b.rs",
            "pub use serde::Serialize;\npub fn f(_: super::a::A) {}",
        ),
    ]))
    .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(cycles(&graph.edges), [["a", "b"]]);
    // The paths of an attribute and its strings, with their escapes decoded, count where what it
    // applies to does: an outer attribute, as the item, field, or other code that follows it, and
    // an inner one, as the region that it is in.
    let a = r#"#[derive(crate::host::b::Trait)]
struct One;
#[cfg_attr(unix, derive(crate::host::c::Trait))]
struct Two;
struct Three {
    #[serde(with = "super::d::codec")]
    value: u8,
    #[serde(
        default,
        deserialize_with = r"crate::host::e::parse",
    )]
    other: u8,
    #[cfg(test)]
    #[serde(with = "super::f::codec")]
    debug: u8,
}
#[derive(crate::host::f::Trait)]
#[cfg(test)]
struct Four;
mod inner {
    #![crate::host::g::attribute]
    #[cfg(test)]
    fn check() {}
}
#[cfg(test)]
mod checks {
    #![crate::host::f::attribute]
}
struct Five {
    #[serde(with = "crate::host::\x68::codec")]
    value: u8,
    #[serde(deserialize_with = "crate::host::\u{69}::parse")]
    other: u8,
    #[serde(serialize_with = "crate::host::\
        j::write")]
    third: u8,
}
"#;
    assert_eq!(
        located_dependencies(&[
            ("src/lib.rs", "pub mod host;"),
            (
                "src/host/mod.rs",
                "pub mod a;\npub mod b;\npub mod c;\npub mod d;\npub mod e;\npub mod f;\n\
                 pub mod g;\npub mod h;\npub mod i;\npub mod j;"
            ),
            ("src/host/a.rs", a),
            ("src/host/b.rs", ""),
            ("src/host/c.rs", ""),
            ("src/host/d.rs", ""),
            ("src/host/e.rs", ""),
            ("src/host/f.rs", ""),
            ("src/host/g.rs", ""),
            ("src/host/h.rs", ""),
            ("src/host/i.rs", ""),
            ("src/host/j.rs", ""),
        ]),
        [
            "a -> b at src/host/a.rs:1",
            "a -> c at src/host/a.rs:3",
            "a -> d at src/host/a.rs:6",
            "a -> e at src/host/a.rs:10",
            "a -> g at src/host/a.rs:21",
            "a -> h at src/host/a.rs:30",
            "a -> i at src/host/a.rs:32",
            "a -> j at src/host/a.rs:35",
        ]
    );
    // Documentation names no dependency, also in a `doc` attribute, as in a doc comment.
    assert_eq!(
        dependencies(&[
            ("src/lib.rs", "pub mod host;"),
            ("src/host/mod.rs", "pub mod a;\npub mod b;"),
            (
                "src/host/a.rs",
                "#[doc = \"[`spawn`](crate::host::b::spawn)\"]\n\
                 #[cfg_attr(unix, doc = \"See crate::host::b::spawn.\")]\n\
                 #[doc(alias = \"crate::host::b::Alias\")]\npub struct A;"
            ),
            ("src/host/b.rs", "pub fn spawn(_: super::a::A) {}"),
        ]),
        ["b -> a"]
    );
}

#[test]
fn paths_name_the_children_that_hold_what_they_name() {
    assert_eq!(
        dependencies(&[
            (
                "src/lib.rs",
                "pub mod host;\nmod protocol;\npub use host::a::Item;\n\
                 pub use self::host::b::{other as renamed};"
            ),
            (
                "src/host/mod.rs",
                "pub mod a;\npub mod b;\npub mod c;\nmod d;\npub mod e;\npub mod f;\n\
                 pub use self::f::Reexported;"
            ),
            ("src/host/a.rs", "pub struct Item;"),
            ("src/host/b/mod.rs", "mod inner;\npub fn other() {}"),
            (
                "src/host/b/inner.rs",
                "use super::super::c::Thing;\n\
                 fn f() { self::g(); super::super::d::h(); super::other(); }\nfn g() {}"
            ),
            (
                "src/host/c.rs",
                "mod nested {\n    fn f() { super::super::e::y(); }\n}\n\
                 pub(in crate::host) fn g() -> crate::Item {\n    crate::renamed();\n    \
                 crate::host::Reexported;\n    crate::host::b::inner::Thing\n}"
            ),
            (
                "src/host/d.rs",
                "pub fn h() { crate::host::d::own(); self::own(); crate::protocol::X; }\n\
                 fn own() {}"
            ),
            (
                "src/host/e.rs",
                "use super::a::{self, Item as Alias};\nuse std::fmt;\npub fn y() {}"
            ),
            ("src/host/f.rs", "pub struct Reexported;"),
        ]),
        [
            "b -> c", "b -> d", "c -> a", "c -> b", "c -> e", "c -> f", "e -> a"
        ]
    );
}

#[test]
fn imports_of_the_root_and_host_resolve_through_chains_and_every_alternative() {
    // `host` imports what the crate root imports from a child, which the root's file, read after
    // `host`'s, declares.
    assert_eq!(
        dependencies(&[
            ("src/lib.rs", "pub mod host;\npub use host::a::Item;"),
            (
                "src/host/mod.rs",
                "pub mod a;\npub mod b;\npub use crate::Item;"
            ),
            ("src/host/a.rs", "pub struct Item;"),
            ("src/host/b.rs", "fn f() -> crate::host::Item { todo!() }"),
        ]),
        ["b -> a"]
    );
    // `cfg`s choose between imports of one name from different children: a path through it
    // depends on both, also through a chain.
    assert_eq!(
        dependencies(&[
            (
                "src/lib.rs",
                "pub mod host;\n#[cfg(unix)]\npub use host::a::Thing;\n#[cfg(windows)]\n\
                 pub use host::b::Thing;"
            ),
            (
                "src/host/mod.rs",
                "pub mod a;\npub mod b;\npub mod c;\npub mod d;\npub use crate::Thing as Other;"
            ),
            ("src/host/a.rs", ""),
            ("src/host/b.rs", ""),
            ("src/host/c.rs", "fn f(_: crate::Thing) {}"),
            ("src/host/d.rs", "use super::Other;"),
        ]),
        ["c -> a", "c -> b", "d -> a", "d -> b"]
    );
    // An import renames a name that its module imports, without a path to that module.
    assert_eq!(
        dependencies(&[
            (
                "src/lib.rs",
                "pub mod host;\npub use host::a::Item;\npub use Item as Alias;"
            ),
            (
                "src/host/mod.rs",
                "pub mod a;\npub mod b;\npub mod c;\npub use c::Thing;\npub use Thing as Other;"
            ),
            ("src/host/a.rs", "pub struct Item;"),
            ("src/host/b.rs", "fn f(_: crate::Alias, _: super::Other) {}"),
            ("src/host/c.rs", "pub struct Thing;"),
        ]),
        ["b -> a", "b -> c"]
    );
    // A module of the crate root hides no import of the same name, which other `cfg`s choose.
    assert_eq!(
        dependencies(&[
            (
                "src/lib.rs",
                "pub mod host;\n#[cfg(unix)]\npub mod backend {\n    pub fn run() {}\n}\n\
                 #[cfg(windows)]\npub use host::b as backend;"
            ),
            ("src/host/mod.rs", "pub mod a;\npub mod b;"),
            (
                "src/host/a.rs",
                "pub fn f() {\n    crate::backend::run();\n}"
            ),
            ("src/host/b.rs", "pub fn run() {\n    super::a::f();\n}"),
        ]),
        ["a -> b", "b -> a"]
    );
    // An import in a function body, of the crate root or `host`, names nothing for their modules.
    assert_eq!(
        dependencies(&[
            (
                "src/lib.rs",
                "pub mod host;\npub use host::a::Item;\nfn helper() {\n    \
                 use crate::host::c::Item;\n}"
            ),
            (
                "src/host/mod.rs",
                "pub mod a;\npub mod b;\npub mod c;\npub mod d;\npub use self::a::Thing;\n\
                 fn local() {\n    use self::d::Thing;\n}"
            ),
            ("src/host/a.rs", "pub struct Item;\npub struct Thing;"),
            ("src/host/b.rs", "fn f(_: crate::Item, _: super::Thing) {}"),
            ("src/host/c.rs", "pub struct Item;"),
            ("src/host/d.rs", "pub struct Thing;"),
        ]),
        ["b -> a"]
    );
    // A macro that a child exports is an item of the crate root, which the child holds, also
    // when a `cfg_attr` may export it, or the child is inline.
    assert_eq!(
        dependencies(&[
            ("src/lib.rs", "pub mod host;"),
            ("src/host/mod.rs", "pub mod a;\npub mod b;"),
            (
                "src/host/a.rs",
                "#[macro_export]\nmacro_rules! shared {\n    () => {};\n}"
            ),
            ("src/host/b.rs", "fn f() {\n    crate::shared!();\n}"),
        ]),
        ["b -> a"]
    );
    assert_eq!(
        dependencies(&[
            ("src/lib.rs", "pub mod host;"),
            (
                "src/host/mod.rs",
                "pub mod a {\n    #[cfg_attr(unix, macro_export)]\n    \
                 macro_rules! shared {\n        () => {};\n    }\n    \
                 fn f() {\n        super::b::g();\n    }\n}\npub mod b;"
            ),
            ("src/host/b.rs", "pub fn g() {\n    crate::shared!();\n}"),
        ]),
        ["a -> b", "b -> a"]
    );
    // Macros have names of their own: a macro named `host` hides no path through `host`, while
    // an invocation of it and an import of its name name it.
    assert_eq!(
        dependencies(&[
            ("src/lib.rs", "pub mod host;"),
            (
                "src/host/mod.rs",
                "pub mod a;\npub mod b;\npub mod c;\npub mod d;"
            ),
            (
                "src/host/a.rs",
                "#[macro_export]\nmacro_rules! host {\n    () => {};\n}\n\
                 #[r#macro_export]\nmacro_rules! shared {\n    () => {};\n}\n\
                 fn f() {\n    crate::host::b::g();\n}"
            ),
            (
                "src/host/b.rs",
                "pub fn g() {\n    crate::host::b::h();\n}\npub fn h() {}"
            ),
            ("src/host/c.rs", "fn f() {\n    crate::host!();\n}"),
            (
                "src/host/d.rs",
                "use crate::shared;\nfn f() {\n    shared!();\n}"
            ),
        ]),
        ["a -> b", "c -> a", "d -> a"]
    );
}

#[test]
fn raw_identifiers_name_what_their_names_do() {
    let graph = analyze(&crate_of(&[
        ("src/lib.rs", "pub mod host;"),
        ("src/host/mod.rs", "pub mod a;\npub mod r#b;"),
        ("src/host/a.rs", "fn f() {\n    super::r#b::r#type();\n}"),
        (
            "src/host/b.rs",
            "pub fn r#type() {}\nuse crate::host::a as r#a;",
        ),
    ]))
    .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(cycles(&graph.edges), [["a", "b"]]);
    let report = report(&graph, &cycles(&graph.edges));
    assert!(
        report.contains("a -> b: src/host/a.rs:2 uses super::b::type"),
        "{report}"
    );
}

#[test]
fn modules_that_the_test_cannot_follow_fail_it() {
    let error = |files: &[(&str, &str)]| analyze(&crate_of(files)).unwrap_err();
    let placed = error(&[
        ("src/lib.rs", "pub mod host;"),
        (
            "src/host/mod.rs",
            "pub mod a;\n#[path = \"other.rs\"]\nmod b;",
        ),
        ("src/host/a.rs", ""),
        ("src/host/other.rs", ""),
    ]);
    assert!(placed.starts_with("src/host/mod.rs:2 "), "{placed}");
    let undeclared = error(&[
        ("src/lib.rs", "pub mod host;"),
        ("src/host/mod.rs", "pub mod a;"),
        ("src/host/a.rs", ""),
        ("src/host/b.rs", ""),
    ]);
    assert!(undeclared.contains(" src/host/b.rs,"), "{undeclared}");
    let hidden = error(&[
        ("src/lib.rs", "pub mod host;"),
        ("src/host/mod.rs", "pub mod a;\npub mod b;"),
        ("src/host/a.rs", "use super::*;"),
        ("src/host/b.rs", ""),
    ]);
    assert!(hidden.starts_with("src/host/a.rs:1 "), "{hidden}");
    let glob = error(&[
        ("src/lib.rs", "pub mod host;\npub use host::a::*;"),
        ("src/host/mod.rs", "pub mod a;"),
        ("src/host/a.rs", ""),
    ]);
    assert!(glob.starts_with("src/lib.rs:2 "), "{glob}");
    let alias = error(&[
        ("src/lib.rs", "pub mod host;\nextern crate self as this;"),
        ("src/host/mod.rs", "pub mod a;"),
        ("src/host/a.rs", ""),
    ]);
    assert!(
        alias.starts_with("src/lib.rs:2 imports the crate root itself"),
        "{alias}"
    );
    let scoped = error(&[
        ("src/lib.rs", "pub mod host;"),
        ("src/host/mod.rs", "#[macro_use]\nmod a;\nmod b;"),
        ("src/host/a.rs", ""),
        ("src/host/b.rs", ""),
    ]);
    assert!(scoped.starts_with("src/host/mod.rs:1 "), "{scoped}");
    let maybe_scoped = error(&[
        ("src/lib.rs", "pub mod host;"),
        (
            "src/host/mod.rs",
            "#[cfg_attr(unix, macro_use)]\nmod a;\nmod b;",
        ),
        ("src/host/a.rs", ""),
        ("src/host/b.rs", ""),
    ]);
    assert!(
        maybe_scoped.starts_with("src/host/mod.rs:1 "),
        "{maybe_scoped}"
    );
    // The same, in a `host` that the crate root holds inline.
    let inline = error(&[(
        "src/lib.rs",
        "pub mod host {\n    #[macro_use]\n    mod a {}\n    mod b {}\n}",
    )]);
    assert!(inline.starts_with("src/lib.rs:2 "), "{inline}");
    let inline = error(&[(
        "src/lib.rs",
        "pub mod host {\n    pub mod a {}\n    #[path = \"other.rs\"]\n    pub mod b;\n}",
    )]);
    assert!(inline.starts_with("src/lib.rs:3 "), "{inline}");
    // The same, with raw identifiers.
    let raw = error(&[
        ("src/lib.rs", "pub mod host;"),
        (
            "src/host/mod.rs",
            "pub mod a;\n#[r#cfg_attr(unix, r#path = \"other.rs\")]\nmod b;",
        ),
        ("src/host/a.rs", ""),
        ("src/host/other.rs", ""),
    ]);
    assert!(raw.starts_with("src/host/mod.rs:2 "), "{raw}");
    let raw = error(&[
        ("src/lib.rs", "pub mod host;"),
        ("src/host/mod.rs", "#[r#macro_use]\nmod a;\nmod b;"),
        ("src/host/a.rs", ""),
        ("src/host/b.rs", ""),
    ]);
    assert!(raw.starts_with("src/host/mod.rs:1 "), "{raw}");
}

#[test]
fn cycles_are_the_strongly_connected_components_of_several_children() {
    let graph = |pairs: &[(&str, &str)]| {
        let edges: BTreeMap<(String, String), Example> = pairs
            .iter()
            .map(|&(from, to)| {
                let example = Example {
                    location: String::new(),
                    path: String::new(),
                };
                ((from.to_owned(), to.to_owned()), example)
            })
            .collect();
        cycles(&edges)
    };
    assert_eq!(
        graph(&[
            ("a", "b"),
            ("b", "c"),
            ("c", "a"),
            ("c", "d"),
            ("d", "e"),
            ("e", "d"),
            ("f", "a"),
            ("e", "g"),
        ]),
        [vec!["a", "b", "c"], vec!["d", "e"]]
    );
    assert!(graph(&[("a", "b"), ("b", "c"), ("a", "c")]).is_empty());
}

#[test]
fn a_cycle_fails_with_one_reference_for_each_of_its_dependencies() {
    let graph = analyze(&crate_of(&[
        ("src/lib.rs", "pub mod host;"),
        ("src/host/mod.rs", "pub mod a;\npub mod b;\npub mod c;"),
        (
            "src/host/a.rs",
            "use crate::host::b::{\n    One,\n    Two,\n};\nuse crate::host::c::Three;",
        ),
        ("src/host/b.rs", "fn f() {\n    super::a::four();\n}"),
        ("src/host/c.rs", ""),
    ]))
    .unwrap();
    let cycles = cycles(&graph.edges);
    assert_eq!(cycles, [["a", "b"]]);
    let report = report(&graph, &cycles);
    assert!(
        report.contains(
            "\na, b:\n  a -> b: src/host/a.rs:2 uses crate::host::b::One\n  \
             b -> a: src/host/b.rs:2 uses super::a::four\n"
        ),
        "{report}"
    );
    assert!(!report.contains("a -> c"), "{report}");
    assert!(
        report.contains("re-export it at its old public path"),
        "{report}"
    );
}
