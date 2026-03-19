// Simplicity "Human-Readable" Language
// Written in 2023 by
//   Andrew Poelstra <simplicity@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

use simplicity::dag::{DagLike, MaxSharing};
use simplicity::jet::Jet;
use simplicity::effects::{annotate_commit, malleability_analysis, missing_write_effects, BranchArm, TransactionField};
use simplicity::human_encoding::Forest;
use simplicity::node::{CommitNode, Inner};
use simplicity::{self, BitIter};

use simplicity::base64::engine::general_purpose::STANDARD;
use std::str::FromStr;
use std::{env, fs};

/// What set of jets to use in the program.
// FIXME this should probably be configurable.
type DefaultJet = simplicity::jet::Elements;

fn usage(process_name: &str) {
    eprintln!("Usage:");
    eprintln!("  {} assemble <filename>", process_name);
    eprintln!("  {} disassemble <base64>", process_name);
    eprintln!("  {} effects <filename|base64>", process_name);
    eprintln!("  {} mermaid <filename|base64>", process_name);
    eprintln!("  {} graph <base64>", process_name);
    eprintln!("  {} relabel <base64>", process_name);
    eprintln!();
    eprintln!("For commands which take an optional expression, the default value is \"main\".");
    eprintln!();
    eprintln!("Run `{} help` to display this message.", process_name);
}

fn invalid_usage(process_name: &str) -> Result<(), String> {
    usage(process_name);
    Err("invalid usage".into())
}

enum Command {
    Assemble,
    Disassemble,
    Effects,
    Graph,
    Mermaid,
    Relabel,
    Help,
}

impl FromStr for Command {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "assemble" => Ok(Command::Assemble),
            "disassemble" => Ok(Command::Disassemble),
            "effects" => Ok(Command::Effects),
            "mermaid" => Ok(Command::Mermaid),
            "graphviz" | "dot" | "graph" => Ok(Command::Graph),
            "relabel" => Ok(Command::Relabel),
            "help" => Ok(Command::Help),
            x => Err(format!("unknown command {}", x)),
        }
    }
}

impl Command {
    fn takes_optional_exprname(&self) -> bool {
        match *self {
            Command::Assemble => false,
            Command::Disassemble => false,
            Command::Effects => false,
            Command::Graph => false,
            Command::Mermaid => false,
            Command::Relabel => false,
            Command::Help => false,
        }
    }
}

/// Parse a program from either a .simpl file path or a base64 string.
fn parse_commit(arg: &str) -> Result<std::sync::Arc<CommitNode<DefaultJet>>, String> {
    if std::path::Path::new(arg).exists() {
        let prog = parse_file(arg)?;
        match prog.roots().get("main") {
            Some(p) => Ok(p.to_commit_node()),
            None => Err("expression `main` not found".into()),
        }
    } else {
        let v = simplicity::base64::Engine::decode(&STANDARD, arg.as_bytes())
            .map_err(|e| format!("failed to parse base64: {}", e))?;
        let iter = BitIter::from(v.into_iter());
        CommitNode::<DefaultJet>::decode(iter).map_err(|e| format!("failed to decode program: {}", e))
    }
}

fn parse_file(name: &str) -> Result<Forest<DefaultJet>, String> {
    let s = fs::read_to_string(name).map_err(|e| format!("failed to read file {}: {}", name, e))?;
    match Forest::parse(&s) {
        Ok(prog) => Ok(prog),
        Err(mut errs) => {
            errs.add_context(std::sync::Arc::from(s));
            eprintln!("Errors:");
            eprintln!("{}", errs);
            eprintln!();
            Err(format!("failed to parse file {}", name))
        }
    }
}

fn main() -> Result<(), String> {
    let mut args = env::args();
    let process_name = args.next().unwrap();
    let process_name = match process_name.rfind('/') {
        Some(idx) => &process_name[idx + 1..],
        None => &process_name[..],
    };

    // Parse command-line args into (command, first_arg, expression)
    let command = match args.next() {
        Some(cmd) => match Command::from_str(&cmd) {
            Ok(cmd) => cmd,
            Err(e) => {
                eprintln!("Error: {}.", e);
                eprintln!();
                return invalid_usage(process_name);
            }
        },
        None => return invalid_usage(process_name),
    };

    if let Command::Help = command {
        usage(process_name);
        return Ok(());
    }

    let first_arg = match args.next() {
        Some(s) => s,
        None => return invalid_usage(process_name),
    };
    let _expression = if command.takes_optional_exprname() {
        args.next().unwrap_or("main".to_owned())
    } else {
        String::new()
    };
    if args.next().is_some() {
        invalid_usage(process_name)?;
    }

    // Execute command
    match command {
        Command::Assemble => {
            let prog = parse_file(&first_arg)?;

            let roots = prog.roots();
            let mut error = false;
            for name in roots.keys() {
                if name.as_ref() != "main" {
                    eprintln!("Expression `{}` not rooted at `main`.", name);
                    error = true;
                }
            }

            if let Some(prog) = roots.get("main") {
                if !error {
                    println!("{}", prog);
                }
            } else {
                eprintln!("Expression `main` not found.");
            }
        }
        Command::Disassemble => {
            let v = simplicity::base64::Engine::decode(&STANDARD, first_arg.as_bytes())
                .map_err(|e| format!("failed to parse base64: {}", e))?;
            let iter = BitIter::from(v.into_iter());
            let commit =
                CommitNode::decode(iter).map_err(|e| format!("failed to decode program: {}", e))?;
            let prog = Forest::<DefaultJet>::from_program(commit);
            println!("{}", prog.string_serialize());
        }
        Command::Effects => {
            let commit = parse_commit(&first_arg)?;
            let summaries = annotate_commit(&commit);
            let root_summary = summaries.last().expect("non-empty program");
            let missing = missing_write_effects(&commit, &summaries);
            let universe = TransactionField::all_elements();
            let malleability = malleability_analysis(&summaries, &universe);

            // ── Root summary ──────────────────────────────────────────────
            println!("=== Root summary ===");
            println!("  can_fail:  {}", if root_summary.can_fail { "yes" } else { "no" });
            if root_summary.reads.is_empty() {
                println!("  reads:     (none)");
            } else {
                println!("  reads:");
                for field in &root_summary.reads {
                    println!("    {}", field);
                }
            }

            // ── Missing write effects ─────────────────────────────────────
            println!();
            println!("=== Missing write effects ===");
            if missing.is_empty() {
                println!("  (none — every branch has a failure path)");
            } else {
                for m in &missing {
                    let arm = match m.arm {
                        BranchArm::Left => "left",
                        BranchArm::Right => "right",
                    };
                    let note = if m.is_pure_unit { " (pure unit — completely inert)" } else { "" };
                    println!("  node #{}: {} arm has no write effect{}", m.node_index, arm, note);
                }
            }

            // ── Malleability ──────────────────────────────────────────────
            println!();
            println!("=== Malleability (uncovered fields) ===");
            if malleability.uncovered.is_empty() {
                println!("  (none — all fields are covered)");
            } else {
                for field in &malleability.uncovered {
                    println!("  {}", field);
                }
            }
        }
        Command::Mermaid => {
            let commit = parse_commit(&first_arg)?;
            let summaries = annotate_commit(&commit);

            // Collect node labels and edges in post-order.
            struct NodeInfo {
                label: String,
                self_fails: bool,
                left: Option<usize>,
                right: Option<usize>,
            }
            let mut nodes: Vec<NodeInfo> = Vec::new();

            for item in (&*commit).post_order_iter::<MaxSharing<simplicity::node::Commit<DefaultJet>>>() {
                let summary = &summaries[item.index];

                let (type_name, self_fails) = match item.node.inner() {
                    Inner::Iden => ("iden".to_owned(), false),
                    Inner::Unit => ("unit".to_owned(), false),
                    Inner::InjL(_) => ("injL".to_owned(), false),
                    Inner::InjR(_) => ("injR".to_owned(), false),
                    Inner::Take(_) => ("take".to_owned(), false),
                    Inner::Drop(_) => ("drop".to_owned(), false),
                    Inner::Comp(_, _) => ("comp".to_owned(), false),
                    Inner::Case(_, _) => ("case".to_owned(), false),
                    Inner::AssertL(_, _) => ("assertL".to_owned(), true),
                    Inner::AssertR(_, _) => ("assertR".to_owned(), true),
                    Inner::Pair(_, _) => ("pair".to_owned(), false),
                    Inner::Disconnect(_, _) => ("disconnect".to_owned(), false),
                    Inner::Witness(_) => ("witness".to_owned(), false),
                    Inner::Fail(_) => ("fail".to_owned(), true),
                    Inner::Word(w) => (format!("const({}b)", w.len()), false),
                    Inner::Jet(j) => {
                        let sf = j.has_write_effect();
                        (format!("{}", j), sf)
                    }
                };

                // Type arrow for this node. Replace unicode × with * for safe display.
                let arrow = item.node.cached_data().arrow();
                let type_arrow = format!("{} -> {}", arrow.source, arrow.target)
                    .replace('×', "*");

                // Effect badges: append fail indicator and reads to the label.
                let fail_badge = if summary.can_fail { "!!" } else { "infallible" };
                let reads_line = if summary.reads.is_empty() {
                    String::new()
                } else {
                    format!("\nread {} fields", summary.reads.len())
                };
                let label = format!("[{}] {} {}\n{}{}", item.index, type_name, fail_badge, type_arrow, reads_line);

                nodes.push(NodeInfo { label, self_fails, left: item.left_index, right: item.right_index });
            }

            println!("flowchart TD");
            for (i, node) in nodes.iter().enumerate() {
                // Escape quotes and newlines for Mermaid node labels.
                let escaped = node.label.replace('"', "#quot;").replace('\n', "<br/>");
                println!("  N{}[\"{}\"]", i, escaped);
            }
            for (i, node) in nodes.iter().enumerate() {
                if let Some(l) = node.left {
                    println!("  N{} --> N{}", i, l);
                }
                if let Some(r) = node.right {
                    println!("  N{} --> N{}", i, r);
                }
            }
            for (i, node) in nodes.iter().enumerate() {
                if node.self_fails {
                    println!("  style N{} fill:#cc0000,color:#fff,stroke:#880000", i);
                }
            }
        }
        Command::Graph => {
            let v = simplicity::base64::Engine::decode(&STANDARD, first_arg.as_bytes())
                .map_err(|e| format!("failed to parse base64: {}", e))?;
            let iter = BitIter::from(v.into_iter());
            let commit = CommitNode::<DefaultJet>::decode(iter)
                .map_err(|e| format!("failed to decode program: {}", e))?;
            println!("{}", commit.display_as_dot());
        }
        Command::Relabel => {
            let prog = parse_file(&first_arg)?;
            println!("{}", prog.string_serialize());
        }
        Command::Help => unreachable!(),
    }

    Ok(())
}
