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

use simplicity::dag::{DagLike, MaxSharing, NoSharing};
use simplicity::jet::Jet;
use simplicity::effects::{annotate_commit, enumerate_code_paths, malleability_analysis, pruneable_nodes, BranchArm, TransactionField};
use simplicity::human_encoding::Forest;
use simplicity::node::{CommitNode, CommitData, Inner, NoDisconnect, NoWitness, Node};
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
    Optimize,
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
            "optimize" => Ok(Command::Optimize),
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
            Command::Optimize => false,
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
        let hex_str = arg.strip_prefix("0x").unwrap_or(arg);
        let v = simplicity::base64::Engine::decode(&STANDARD, arg.as_bytes())
            .or_else(|_| {
                (0..hex_str.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
                    .collect::<Result<Vec<u8>, _>>()
            })
            .map_err(|e| format!("failed to parse program: {}", e))?;
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
            let hex_str = first_arg.strip_prefix("0x").unwrap_or(&first_arg);
            let v = simplicity::base64::Engine::decode(&STANDARD, first_arg.as_bytes())
                .or_else(|_| {
                    (0..hex_str.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
                        .collect::<Result<Vec<u8>, _>>()
                })
                .map_err(|e| format!("failed to parse program: {}", e))?;
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
                let mut bare_units: std::collections::HashSet<usize> =
                    std::collections::HashSet::new();
                for item in (&*commit).post_order_iter::<MaxSharing<simplicity::node::Commit<DefaultJet>>>() {
                    if pruneable_set.contains(&item.index) {
                        if let Some(l) = item.left_index { subsumed.insert(l); }
                        if let Some(r) = item.right_index { subsumed.insert(r); }
                    }
                    if matches!(item.node.inner(), Inner::Unit) {
                        bare_units.insert(item.index);
                    }
                }
                let top_level: Vec<_> = pruneable.iter()
                    .filter(|p| !subsumed.contains(&p.node_index))
                    .filter(|p| !bare_units.contains(&p.node_index))
                    .collect();
                if !top_level.is_empty() {
                    println!();
                    println!("=== WARNING: pruneable subtrees ===");
                    println!("  {} subtree(s) have return type Unit with no side effects", top_level.len());
                    println!("  and can each be replaced with a bare `unit` node:");
                    for p in &top_level {
                        println!("  node #{}", p.node_index);
                    }
                }
            }

            // ── Code path analysis ──────────────────────────────────────
            let (paths, truncated) = enumerate_code_paths(&commit, 64);
            let with_write = paths.iter().filter(|p| p.can_fail).count();
            let without_write = paths.len() - with_write;
            println!();
            println!("=== Code path analysis ===");
            println!("  {} path(s) total{}: {} with write effects, {} without",
                paths.len(),
                if truncated { " (truncated)" } else { "" },
                with_write,
                without_write,
            );
            for (i, path) in paths.iter().enumerate() {
                let choices: Vec<String> = path.choices.iter()
                    .map(|(sid, arm)| {
                        let arm_str = match arm {
                            BranchArm::Left => "left",
                            BranchArm::Right => "right",
                        };
                        format!("case #{} -> {}", sid, arm_str)
                    })
                    .collect();
                let path_label = if choices.is_empty() {
                    "(no branches)".to_owned()
                } else {
                    choices.join(", ")
                };
                let reads = if path.reads.is_empty() {
                    "no reads".to_owned()
                } else {
                    format!("reads {} fields", path.reads.len())
                };
                let fail = if path.can_fail { "can fail" } else { "cannot fail" };
                let warning = if !path.can_fail { " << NO WRITE EFFECT" } else { "" };
                let path_uncovered: Vec<_> = universe.difference(&path.reads).collect();
                println!();
                println!("  Path {}: {}", i + 1, path_label);
                println!("    {}, {}{}", reads, fail, warning);
                if path_uncovered.len() < universe.len() && !path_uncovered.is_empty() {
                    println!("    uncovered fields ({}):", path_uncovered.len());
                    for field in &path_uncovered {
                        println!("      {}", field);
                    }
                } else if path_uncovered.is_empty() {
                    println!("    all fields covered");
                } else {
                    println!("    no fields covered (reads nothing)");
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
            let mut sharing_index: HashMap<usize, usize> = HashMap::new();
            for item in (&*commit).post_order_iter::<MaxSharing<simplicity::node::Commit<DefaultJet>>>() {
                let ptr = item.node as *const _ as usize;
                summaries.insert(ptr, summaries_vec[item.index].clone());
                sharing_index.insert(ptr, item.index);
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
                /// All Mermaid node IDs in this subtree (for subgraph containment).
                members: Vec<String>,
            }
            let mut flow: Vec<FlowInfo> = Vec::new();
            let mut node_defs: Vec<String> = Vec::new();
            let mut edges: Vec<String> = Vec::new();
            let mut subgraphs: Vec<String> = Vec::new();
            // Red node IDs collected separately so they override the green jet style.
            let mut red_nodes: Vec<String> = Vec::new();

            for item in (&*commit).post_order_iter::<NoSharing>() {
                let i = item.index;
                let nid = format!("N{}", i);
                let ptr = item.node as *const _ as usize;
                let sid = sharing_index.get(&ptr).copied().unwrap_or(i);
                let can_fail = summaries.get(&ptr).map_or(false, |s| s.can_fail);

                match item.node.inner() {
                    // comp: sequential — s feeds into t, wrapped in a subgraph box
                    Inner::Comp(_, _) => {
                        let li = item.left_index.unwrap();
                        let ri = item.right_index.unwrap();
                        let suffix = effect_suffix(ptr);
                        edges.push(format!("  {} --> {}", flow[li].end, flow[ri].start));
                        let sg_id = format!("SG{}", i);
                        subgraphs.push(format!("  subgraph {}[\"[{}] comp{}\"]", sg_id, sid, suffix));
                        // Collect all member node IDs from both children.
                        let mut members: Vec<String> = Vec::new();
                        members.extend(flow[li].members.iter().cloned());
                        members.extend(flow[ri].members.iter().cloned());
                        for m in &members {
                            subgraphs.push(format!("    {}", m));
                        }
                        subgraphs.push("  end".to_owned());
                        if can_fail {
                            subgraphs.push(format!("  style {} stroke:#cc0000,stroke-width:2px", sg_id));
                        }
                        let start = flow[li].start.clone();
                        let end = flow[ri].end.clone();
                        members.push(sg_id);
                        flow.push(FlowInfo { start, end, members });
                    }

                    // pair: parallel — split into s and t, then join
                    Inner::Pair(_, _) | Inner::Disconnect(_, _) => {
                        let li = item.left_index.unwrap();
                        let ri = item.right_index.unwrap();
                        let split_id = format!("SP{}", i);
                        let join_id = format!("J{}", i);
                        let out_type = item.node.cached_data().arrow().target.to_string().replace('×', "*");
                        let suffix = effect_suffix(ptr);
                        node_defs.push(format!("  {}(\"[{}] pair\")", split_id, sid));
                        node_defs.push(format!("  {}(\"[{}] -&gt; {}{}\")", join_id, sid, out_type, suffix));
                        edges.push(format!("  {} --> {}", split_id, flow[li].start));
                        edges.push(format!("  {} --> {}", split_id, flow[ri].start));
                        edges.push(format!("  {} --> {}", flow[li].end, join_id));
                        edges.push(format!("  {} --> {}", flow[ri].end, join_id));
                        if can_fail { red_nodes.push(join_id.clone()); }
                        let mut members = vec![split_id.clone(), join_id.clone()];
                        members.extend(flow[li].members.iter().cloned());
                        members.extend(flow[ri].members.iter().cloned());
                        flow.push(FlowInfo { start: split_id, end: join_id, members });
                    }

                    // case: conditional branch — decision routes to s or t, then join
                    Inner::Case(_, _) => {
                        let li = item.left_index.unwrap();
                        let ri = item.right_index.unwrap();
                        let dec_id = format!("D{}", i);
                        let join_id = format!("J{}", i);
                        let out_type = item.node.cached_data().arrow().target.to_string().replace('×', "*");
                        let suffix = effect_suffix(ptr);
                        node_defs.push(format!("  {}{{\"[{}] case\"}}", dec_id, sid));
                        node_defs.push(format!("  {}(\"[{}] -&gt; {}{}\")", join_id, sid, out_type, suffix));
                        // Emit right edge before left so Mermaid places left on the left side.
                        edges.push(format!("  {} -->|right| {}", dec_id, flow[ri].start));
                        edges.push(format!("  {} -->|left| {}", dec_id, flow[li].start));
                        edges.push(format!("  {} --> {}", flow[li].end, join_id));
                        edges.push(format!("  {} --> {}", flow[ri].end, join_id));
                        if can_fail { red_nodes.push(join_id.clone()); }
                        let mut members = vec![dec_id.clone(), join_id.clone()];
                        members.extend(flow[li].members.iter().cloned());
                        members.extend(flow[ri].members.iter().cloned());
                        flow.push(FlowInfo { start: dec_id, end: join_id, members });
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
                        let ci = item.left_index.unwrap();
                        node_defs.push(format!("  {}[\"[{}] {}{}\"]", nid, sid, base_label, suffix));
                        if can_fail { red_nodes.push(nid.clone()); }
                        edges.push(format!("  {} --> {}", flow[ci].end, nid));
                        let mut members = vec![nid.clone()];
                        members.extend(flow[ci].members.iter().cloned());
                        flow.push(FlowInfo { start: flow[ci].start.clone(), end: nid, members });
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
                        node_defs.push(format!("  {}[\"[{}] {}{}\"]", nid, sid, base_label, suffix));
                        if is_jet {
                            node_defs.push(format!("  style {} fill:#2a7,color:#fff,stroke:#195", nid));
                        }
                        if can_fail { red_nodes.push(nid.clone()); }
                        flow.push(FlowInfo { start: nid.clone(), end: nid.clone(), members: vec![nid] });
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
            for sg in &subgraphs {
                println!("{}", sg);
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
        Command::Optimize => {
            let commit = parse_commit(&first_arg)?;
            let summaries = annotate_commit(&commit);

            // Find top-level pruneable nodes (same logic as effects command).
            let pruneable = pruneable_nodes(&summaries);
            let pruneable_set: std::collections::HashSet<usize> =
                pruneable.iter().map(|p| p.node_index).collect();
            let mut subsumed: std::collections::HashSet<usize> =
                std::collections::HashSet::new();
            let mut bare_units: std::collections::HashSet<usize> =
                std::collections::HashSet::new();
            for item in (&*commit).post_order_iter::<MaxSharing<simplicity::node::Commit<DefaultJet>>>() {
                if pruneable_set.contains(&item.index) {
                    if let Some(l) = item.left_index { subsumed.insert(l); }
                    if let Some(r) = item.right_index { subsumed.insert(r); }
                }
                if matches!(item.node.inner(), Inner::Unit) {
                    bare_units.insert(item.index);
                }
            }
            let replace_set: std::collections::HashSet<usize> = pruneable.iter()
                .map(|p| p.node_index)
                .filter(|idx| !subsumed.contains(idx))
                .filter(|idx| !bare_units.contains(idx))
                .collect();

            if replace_set.is_empty() {
                eprintln!("Nothing to optimize.");
                println!("{}", commit);
            } else {
                eprintln!("Replacing {} pruneable subtree(s) with unit.", replace_set.len());

                // Rebuild the DAG, replacing pruneable subtrees with unit nodes.
                let mut rebuilt: Vec<std::sync::Arc<CommitNode<DefaultJet>>> = Vec::new();
                for item in (&*commit).post_order_iter::<MaxSharing<simplicity::node::Commit<DefaultJet>>>() {
                    if replace_set.contains(&item.index) {
                        // Replace with a unit node that keeps the same type arrow.
                        let arrow = item.node.cached_data().arrow().shallow_clone();
                        let data = CommitData::from_final(arrow, Inner::Unit.as_ref());
                        rebuilt.push(std::sync::Arc::new(Node::from_parts(Inner::Unit, std::sync::Arc::new(data))));
                    } else {
                        // Rebuild node with (potentially replaced) children.
                        let new_inner = match item.node.inner() {
                            Inner::Iden => Inner::Iden,
                            Inner::Unit => Inner::Unit,
                            Inner::Fail(e) => Inner::Fail(*e),
                            Inner::Jet(j) => Inner::Jet(j.clone()),
                            Inner::Word(w) => Inner::Word(w.shallow_clone()),
                            Inner::Witness(_) => Inner::Witness(NoWitness),
                            Inner::Disconnect(_, _) => Inner::Disconnect(
                                std::sync::Arc::clone(&rebuilt[item.left_index.unwrap()]),
                                NoDisconnect,
                            ),
                            Inner::InjL(_) => Inner::InjL(std::sync::Arc::clone(&rebuilt[item.left_index.unwrap()])),
                            Inner::InjR(_) => Inner::InjR(std::sync::Arc::clone(&rebuilt[item.left_index.unwrap()])),
                            Inner::Take(_) => Inner::Take(std::sync::Arc::clone(&rebuilt[item.left_index.unwrap()])),
                            Inner::Drop(_) => Inner::Drop(std::sync::Arc::clone(&rebuilt[item.left_index.unwrap()])),
                            Inner::AssertL(_, cmr) => Inner::AssertL(
                                std::sync::Arc::clone(&rebuilt[item.left_index.unwrap()]),
                                *cmr,
                            ),
                            Inner::AssertR(cmr, _) => Inner::AssertR(
                                *cmr,
                                std::sync::Arc::clone(&rebuilt[item.right_index.unwrap()]),
                            ),
                            Inner::Comp(_, _) => Inner::Comp(
                                std::sync::Arc::clone(&rebuilt[item.left_index.unwrap()]),
                                std::sync::Arc::clone(&rebuilt[item.right_index.unwrap()]),
                            ),
                            Inner::Case(_, _) => Inner::Case(
                                std::sync::Arc::clone(&rebuilt[item.left_index.unwrap()]),
                                std::sync::Arc::clone(&rebuilt[item.right_index.unwrap()]),
                            ),
                            Inner::Pair(_, _) => Inner::Pair(
                                std::sync::Arc::clone(&rebuilt[item.left_index.unwrap()]),
                                std::sync::Arc::clone(&rebuilt[item.right_index.unwrap()]),
                            ),
                        };
                        let arrow = item.node.cached_data().arrow().shallow_clone();
                        let data_inner = new_inner.as_ref().map(|n| n.cached_data()).map_disconnect(|_| &NoDisconnect).map_witness(|_| &NoWitness);
                        let data = CommitData::from_final(arrow, data_inner);
                        rebuilt.push(std::sync::Arc::new(Node::from_parts(new_inner, std::sync::Arc::new(data))));
                    }
                }
                let optimized = rebuilt.pop().unwrap();
                println!("{}", optimized);
            }
        }
        Command::Relabel => {
            let prog = parse_file(&first_arg)?;
            println!("{}", prog.string_serialize());
        }
        Command::Help => unreachable!(),
    }

    Ok(())
}
