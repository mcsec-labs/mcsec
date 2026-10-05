//! Unsafe Java deserialization, the bug class behind BleedingPipe.
//!
//! `ObjectInputStream.readObject` instantiates whatever serializable class the
//! input names, so feeding it data an attacker controls can run code through
//! gadget classes on the classpath. The rule flags reads from streams a
//! method creates itself, and rates them by where the stream's data comes
//! from according to the data flow engine.
//!
//! Data entering through another method, such as bytes a packet handler
//! passes in as a parameter, needs tracking across methods and is rated as
//! if the source were unknown for now.

use std::collections::HashSet;

use super::Context;
use crate::class_file::{Operand, op};
use crate::dataflow::{self, Alloc, Frame, Labels, Policy, Site, Value};
use crate::finding::{EvidenceStep, Finding, MethodRef, Severity};

pub const RULE_ID: &str = "unsafe-deserialization";

const OBJECT_INPUT_STREAM: &str = "java/io/ObjectInputStream";
const OBJECT_INPUT: &str = "java/io/ObjectInput";
/// Holds the static `setObjectInputFilter(stream, filter)` on Java 8, as
/// `sun.misc` and `java.io` place it in different releases.
const FILTER_CONFIGS: &[&str] = &[
    "java/io/ObjectInputFilter$Config",
    "sun/misc/ObjectInputFilter$Config",
];

/// Types that carry bytes received from the network. Minecraft class names
/// are given as they appear in shipped jars for each loader generation:
/// MCP names on Forge up to 1.16, Mojang names on later Forge and NeoForge,
/// and intermediary names on Fabric and Quilt.
const NETWORK_TYPES: &[&str] = &[
    "io/netty/buffer/ByteBuf",
    "io/netty/buffer/ByteBufInputStream",
    "net/minecraft/network/PacketBuffer",
    "net/minecraft/network/FriendlyByteBuf",
    "net/minecraft/class_2540",
    "net/minecraftforge/fml/common/network/internal/FMLProxyPacket",
    "cpw/mods/fml/common/network/internal/FMLProxyPacket",
];

const NETWORK: Labels = Labels(1);

struct NetworkSources<'c, 'r, 'a> {
    context: &'c Context<'r, 'a>,
}

impl Policy for NetworkSources<'_, '_, '_> {
    fn parameter(&self, ty: &str, receiver: bool) -> Option<(Labels, String)> {
        if !is_network_type(self.context, ty) {
            return None;
        }
        let description = if receiver {
            format!("Runs on network data, as {ty} is a network type")
        } else {
            format!("Receives network data as a parameter of type {ty}")
        };
        Some((NETWORK, description))
    }

    fn call(&self, owner: &str, name: &str, _descriptor: &str) -> Option<(Labels, String)> {
        is_network_type(self.context, owner).then(|| {
            (
                NETWORK,
                format!("Reads network data through {owner}.{name}"),
            )
        })
    }

    fn allocation(&self, _class: &str) -> Option<(Labels, String)> {
        // A freshly created buffer is empty, not network data.
        None
    }
}

/// A `readObject` call on a stream the method created.
struct Read {
    offset: u32,
    stream: Value,
    created: Alloc,
}

pub(crate) fn check(context: &Context, findings: &mut Vec<Finding>) {
    let class = &context.parsed.class;
    let pool = &class.constant_pool;
    let policy = NetworkSources { context };
    for method in &class.methods {
        let (Ok(name), Ok(descriptor)) = (method.name(pool), method.descriptor(pool)) else {
            continue;
        };

        let mut reads = Vec::new();
        let mut filtered = HashSet::new();
        dataflow::analyze(class, method, &policy, &mut |site, frame| {
            observe(context, site, frame, &mut reads, &mut filtered);
        });

        let method_ref = MethodRef {
            name: name.into_owned(),
            descriptor: descriptor.into_owned(),
        };
        if let Some(finding) = finding(context, &method_ref, reads, &filtered) {
            findings.push(finding);
        }
    }
}

fn observe(
    context: &Context,
    site: &Site,
    frame: &Frame,
    reads: &mut Vec<Read>,
    filtered: &mut HashSet<u32>,
) {
    let ins = site.instruction;
    let index = match (ins.opcode, &ins.operand) {
        (op::INVOKEVIRTUAL | op::INVOKESTATIC, Operand::Constant(index)) => *index,
        (op::INVOKEINTERFACE, Operand::InvokeInterface { index, .. }) => *index,
        _ => return,
    };
    let Ok(target) = site.pool.member_ref(index) else {
        return;
    };
    let owner = target.class_name.as_ref();

    let reads_object = matches!(target.name.as_ref(), "readObject" | "readUnshared")
        && target.descriptor == "()Ljava/lang/Object;";
    if reads_object && (owner == OBJECT_INPUT || is_object_input_stream(context, owner)) {
        // Only streams this method creates. A stream received as a
        // parameter belongs to whoever created it, as in Java's own
        // readObject(ObjectInputStream) serialization hooks.
        if let Some(stream) = frame.peek(0)
            && let Some(created) = stream
                .alloc
                .clone()
                .filter(|a| is_object_input_stream(context, &a.class))
        {
            reads.push(Read {
                offset: ins.offset,
                stream: stream.clone(),
                created,
            });
        }
        return;
    }

    // Both the instance call `stream.setObjectInputFilter(filter)` and the
    // static `Config.setObjectInputFilter(stream, filter)` leave the stream
    // second from the top.
    let sets_filter = target.name == "setObjectInputFilter"
        && (FILTER_CONFIGS.contains(&owner) || is_object_input_stream(context, owner));
    if sets_filter && let Some(alloc) = frame.peek(1).and_then(|s| s.alloc.as_ref()) {
        filtered.insert(alloc.offset);
    }
}

fn severity_of(read: &Read, filtered: &HashSet<u32>) -> Severity {
    if filtered.contains(&read.created.offset) || &*read.created.class != OBJECT_INPUT_STREAM {
        Severity::Notice
    } else if read.stream.labels.contains(NETWORK) {
        Severity::Critical
    } else {
        Severity::Warning
    }
}

fn finding(
    context: &Context,
    method: &MethodRef,
    reads: Vec<Read>,
    filtered: &HashSet<u32>,
) -> Option<Finding> {
    // One finding per method, for its most severe read.
    let read = reads
        .into_iter()
        .max_by_key(|read| (severity_of(read, filtered), std::cmp::Reverse(read.offset)))?;
    let severity = severity_of(&read, filtered);
    let title = match severity {
        Severity::Critical => "Deserializes network data with ObjectInputStream",
        Severity::Warning => "Deserializes data with ObjectInputStream",
        Severity::Notice => "Deserializes with a filtered or custom ObjectInputStream",
    };

    let step = |description: String, offset: u32| EvidenceStep {
        description,
        location: context.location(method, offset),
    };
    let mut evidence = Vec::new();
    if let Some(origin) = &read.stream.origin {
        evidence.push(step(origin.description.to_string(), origin.offset));
    }
    let created = &read.created;
    evidence.push(step(format!("Creates {}", created.class), created.offset));
    if filtered.contains(&created.offset) {
        evidence.push(step(
            "Installs an ObjectInputFilter that limits the classes it accepts".to_owned(),
            created.offset,
        ));
    } else if &*created.class != OBJECT_INPUT_STREAM {
        evidence.push(step(
            format!(
                "{} extends ObjectInputStream and may restrict the classes it resolves",
                created.class
            ),
            created.offset,
        ));
    }
    evidence.push(step(
        "Calls readObject, which instantiates any serializable class the data names".to_owned(),
        read.offset,
    ));

    Some(Finding {
        rule_id: RULE_ID.to_owned(),
        severity,
        title: title.to_owned(),
        location: context.location(method, read.offset),
        evidence,
    })
}

fn is_object_input_stream(context: &Context, name: &str) -> bool {
    context.hierarchy.extends_any(name, &[OBJECT_INPUT_STREAM])
}

fn is_network_type(context: &Context, name: &str) -> bool {
    context.hierarchy.extends_any(name, NETWORK_TYPES)
}
