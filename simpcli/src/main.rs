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

use simplicity::dag::{DagLike, InternalSharing, MaxSharing, NoSharing};
use simplicity::jet::Jet;
use simplicity::effects::{annotate_commit, malleability_analysis, missing_write_effects, pruneable_nodes, BranchArm, TransactionField};
use simplicity::human_encoding::Forest;
use simplicity::node::{CommitNode, Inner};
use simplicity::{self, BitIter};

use simplicity::base64::engine::general_purpose::STANDARD;
use std::collections::HashMap;
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
    eprintln!("  {} flowchart <filename|base64>", process_name);
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
    Flowchart,
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
            "flowchart" => Ok(Command::Flowchart),
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
            Command::Flowchart => false,
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

            // ── Pruneable subtrees ────────────────────────────────────────
            // A node is pruneable when its output type is Unit and the subtree
            // has no side effects, so it is equivalent to a bare `unit`.
            // We report only top-level roots: if a pruneable node's parent is
            // also pruneable, it is already subsumed and not shown separately.
            let pruneable = pruneable_nodes(&summaries);
            if !pruneable.is_empty() {
                let pruneable_set: std::collections::HashSet<usize> =
                    pruneable.iter().map(|p| p.node_index).collect();
                let mut subsumed: std::collections::HashSet<usize> =
                    std::collections::HashSet::new();
                for item in (&*commit).post_order_iter::<MaxSharing<simplicity::node::Commit<DefaultJet>>>() {
                    if pruneable_set.contains(&item.index) {
                        if let Some(l) = item.left_index { subsumed.insert(l); }
                        if let Some(r) = item.right_index { subsumed.insert(r); }
                    }
                }
                let top_level: Vec<_> = pruneable.iter()
                    .filter(|p| !subsumed.contains(&p.node_index))
                    .collect();
                println!();
                println!("=== WARNING: pruneable subtrees ===");
                println!("  {} subtree(s) have return type Unit with no side effects", top_level.len());
                println!("  and can each be replaced with a bare `unit` node:");
                for p in &top_level {
                    println!("  node #{}", p.node_index);
                }
            }
        }
        Command::Flowchart => {
            let commit = parse_commit(&first_arg)?;

            // annotate_commit uses MaxSharing indices internally. Build a pointer→summary
            // map so we can look up effects during the NoSharing traversal, which assigns
            // different (higher) indices to revisited nodes.
            let summaries_vec = annotate_commit(&commit);
            let mut summaries: HashMap<usize, simplicity::effects::EffectSummary> = HashMap::new();
            for item in (&*commit).post_order_iter::<MaxSharing<simplicity::node::Commit<DefaultJet>>>() {
                summaries.insert(item.node as *const _ as usize, summaries_vec[item.index].clone());
            }

            // Build an effect suffix string for a node label (HTML newlines for Mermaid).
            let effect_suffix = |ptr: usize| -> String {
                let Some(s) = summaries.get(&ptr) else { return String::new() };
                let mut parts = Vec::<String>::new();
                if s.can_fail { parts.push("[can fail]".to_owned()); }
                if !s.reads.is_empty() { parts.push(format!("reads {} fields", s.reads.len())); }
                if parts.is_empty() { String::new() } else { format!("<br/>{}", parts.join("<br/>")) }
            };

            // For each node, track its entry and exit point in the Mermaid diagram.
            // Leaves use the same node ID for both. Structural combinators may use
            // separate split/join nodes.
            struct FlowInfo {
                start: String,
                end: String,
            }
            let mut flow: Vec<FlowInfo> = Vec::new();
            let mut node_defs: Vec<String> = Vec::new();
            let mut edges: Vec<String> = Vec::new();
            // Red node IDs collected separately so they override the green jet style.
            let mut red_nodes: Vec<String> = Vec::new();

            for item in (&*commit).post_order_iter::<NoSharing>() {
                let i = item.index;
                let nid = format!("N{}", i);
                let ptr = item.node as *const _ as usize;
                let can_fail = summaries.get(&ptr).map_or(false, |s| s.can_fail);

                match item.node.inner() {
                    // comp: sequential — s feeds into t
                    Inner::Comp(_, _) => {
                        let s = &flow[item.left_index.unwrap()];
                        let t = &flow[item.right_index.unwrap()];
                        edges.push(format!("  {} --> {}", s.end, t.start));
                        flow.push(FlowInfo { start: s.start.clone(), end: t.end.clone() });
                    }

                    // pair: parallel — split into s and t, then join
                    Inner::Pair(_, _) | Inner::Disconnect(_, _) => {
                        let s = &flow[item.left_index.unwrap()];
                        let t = &flow[item.right_index.unwrap()];
                        let split_id = format!("SP{}", i);
                        let join_id = format!("J{}", i);
                        let out_type = item.node.cached_data().arrow().target.to_string().replace('×', "*");
                        let suffix = effect_suffix(ptr);
                        node_defs.push(format!("  {}(\"[{}] pair\")", split_id, i));
                        node_defs.push(format!("  {}(\"[{}] -&gt; {}{}\")", join_id, i, out_type, suffix));
                        edges.push(format!("  {} --> {}", split_id, s.start));
                        edges.push(format!("  {} --> {}", split_id, t.start));
                        edges.push(format!("  {} --> {}", s.end, join_id));
                        edges.push(format!("  {} --> {}", t.end, join_id));
                        if can_fail { red_nodes.push(join_id.clone()); }
                        flow.push(FlowInfo { start: split_id, end: join_id });
                    }

                    // case: conditional branch — decision routes to s or t, then join
                    Inner::Case(_, _) => {
                        let s = &flow[item.left_index.unwrap()];
                        let t = &flow[item.right_index.unwrap()];
                        let dec_id = format!("D{}", i);
                        let join_id = format!("J{}", i);
                        let out_type = item.node.cached_data().arrow().target.to_string().replace('×', "*");
                        let suffix = effect_suffix(ptr);
                        node_defs.push(format!("  {}{{\"[{}] case\"}}", dec_id, i));
                        node_defs.push(format!("  {}(\"[{}] -&gt; {}{}\")", join_id, i, out_type, suffix));
                        edges.push(format!("  {} -->|left| {}", dec_id, s.start));
                        edges.push(format!("  {} -->|right| {}", dec_id, t.start));
                        edges.push(format!("  {} --> {}", s.end, join_id));
                        edges.push(format!("  {} --> {}", t.end, join_id));
                        if can_fail { red_nodes.push(join_id.clone()); }
                        flow.push(FlowInfo { start: dec_id, end: join_id });
                    }

                    // Unary wrappers: child flows through, then this node
                    Inner::InjL(_) | Inner::InjR(_) | Inner::Take(_) | Inner::Drop(_)
                    | Inner::AssertL(_, _) | Inner::AssertR(_, _) => {
                        let base_label = match item.node.inner() {
                            Inner::InjL(_) => "injL",
                            Inner::InjR(_) => "injR",
                            Inner::Take(_) => "take",
                            Inner::Drop(_) => "drop",
                            Inner::AssertL(_, _) => "assertL",
                            Inner::AssertR(_, _) => "assertR",
                            _ => unreachable!(),
                        };
                        let suffix = effect_suffix(ptr);
                        let child = &flow[item.left_index.unwrap()];
                        node_defs.push(format!("  {}[\"[{}] {}{}\"]", nid, i, base_label, suffix));
                        if can_fail { red_nodes.push(nid.clone()); }
                        edges.push(format!("  {} --> {}", child.end, nid));
                        flow.push(FlowInfo { start: child.start.clone(), end: nid });
                    }

                    // Leaves: single box
                    _ => {
                        let is_jet = matches!(item.node.inner(), Inner::Jet(_));
                        let base_label = match item.node.inner() {
                            Inner::Iden => "iden".to_owned(),
                            Inner::Unit => "unit".to_owned(),
                            Inner::Witness(_) => "witness".to_owned(),
                            Inner::Fail(_) => "fail".to_owned(),
                            Inner::Word(w) => format!("const({}b)", w.len()),
                            Inner::Jet(j) => format!("{}", j),
                            _ => "?".to_owned(),
                        };
                        let suffix = effect_suffix(ptr);
                        node_defs.push(format!("  {}[\"[{}] {}{}\"]", nid, i, base_label, suffix));
                        if is_jet {
                            node_defs.push(format!("  style {} fill:#2a7,color:#fff,stroke:#195", nid));
                        }
                        if can_fail { red_nodes.push(nid.clone()); }
                        flow.push(FlowInfo { start: nid.clone(), end: nid });
                    }
                }
            }

            // The last node visited in post-order is the root.
            let root_start = flow.last().map(|f| f.start.clone()).unwrap_or_default();
            let root_end = flow.last().map(|f| f.end.clone()).unwrap_or_default();

            println!("%%{{init: {{\"flowchart\": {{\"defaultRenderer\": \"elk\"}}, \"elk\": {{\"elk.layered.layering.strategy\": \"LONGEST_PATH\"}}}}}}%%");
            println!("flowchart TD");
            println!("  START([START])");
            println!("  END([END])");
            println!("  START --> {}", root_start);
            println!("  {} --> END", root_end);
            for def in &node_defs {
                println!("{}", def);
            }
            for edge in &edges {
                println!("{}", edge);
            }
            for id in &red_nodes {
                println!("  style {} fill:#cc0000,color:#fff,stroke:#880000", id);
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
