//! Unsafe Java deserialization, the BleedingPipe pattern.
//!
//! `ObjectInputStream.readObject` instantiates whatever serializable class the
//! input names, so feeding it data an attacker controls can run code through
//! gadget classes on the classpath. The rule flags methods that create an
//! `ObjectInputStream` and read an object from it.
//!
//! Checks one method at a time. A stream created in one method and read in
//! another, or bytes passed in from a packet handler as a parameter, need
//! tracking across methods and are rated as if the source were unknown.

use super::Context;
use crate::class_file::{Instruction, Operand, op};
use crate::finding::{EvidenceStep, Finding, MethodRef, Severity};

pub const RULE_ID: &str = "unsafe-deserialization";

const OBJECT_INPUT_STREAM: &str = "java/io/ObjectInputStream";
const OBJECT_INPUT: &str = "java/io/ObjectInput";

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

pub(crate) fn check(context: &Context, findings: &mut Vec<Finding>) {
    let class = &context.parsed.class;
    let pool = &class.constant_pool;
    for method in &class.methods {
        let (Ok(name), Ok(descriptor)) = (method.name(pool), method.descriptor(pool)) else {
            continue;
        };
        let Ok(Some(code)) = method.code(pool) else {
            continue;
        };
        let method_ref = MethodRef {
            name: name.into_owned(),
            descriptor: descriptor.into_owned(),
        };

        let mut scan = MethodScan::default();
        if let Some(param) = parameter_types(&method_ref.descriptor)
            .into_iter()
            .find(|t| is_network_type(context, t))
        {
            scan.network = Some(Source::Parameter(param));
        }
        // A method that fails to decode partway is checked up to the failure.
        for instruction in code.instructions().map_while(Result::ok) {
            scan.visit(context, &instruction);
        }

        if let Some(finding) = scan.finding(context, &method_ref) {
            findings.push(finding);
        }
    }
}

enum Source {
    /// The method receives network data as a parameter of this type.
    Parameter(String),
    /// The method calls into or creates this network type at an offset.
    Call { offset: u32, owner: String },
}

#[derive(Default)]
struct MethodScan {
    /// Where an `ObjectInputStream`, or a subclass, is created, and its type.
    created: Option<(u32, String)>,
    /// Offset of the first `readObject` or `readUnshared` call.
    read: Option<u32>,
    /// Offset of a `setObjectInputFilter` call, which limits the classes read.
    filtered: Option<u32>,
    network: Option<Source>,
}

impl MethodScan {
    fn visit(&mut self, context: &Context, instruction: &Instruction) {
        let pool = &context.parsed.class.constant_pool;
        let offset = instruction.offset;
        match (instruction.opcode, &instruction.operand) {
            (op::NEW, Operand::Constant(index)) => {
                let Ok(created) = pool.class_name(*index) else {
                    return;
                };
                if self.created.is_none() && is_object_input_stream(context, &created) {
                    self.created = Some((offset, created.into_owned()));
                } else if self.network.is_none() && is_network_type(context, &created) {
                    self.network = Some(Source::Call {
                        offset,
                        owner: created.into_owned(),
                    });
                }
            }
            (
                op::INVOKEVIRTUAL | op::INVOKESPECIAL | op::INVOKESTATIC,
                Operand::Constant(index),
            )
            | (op::INVOKEINTERFACE, Operand::InvokeInterface { index, .. }) => {
                let Ok(target) = pool.member_ref(*index) else {
                    return;
                };
                let owner = target.class_name.as_ref();
                let stream_call = owner == OBJECT_INPUT || is_object_input_stream(context, owner);
                let reads_object = matches!(target.name.as_ref(), "readObject" | "readUnshared")
                    && target.descriptor == "()Ljava/lang/Object;";
                if stream_call && reads_object {
                    self.read.get_or_insert(offset);
                } else if stream_call && target.name == "setObjectInputFilter" {
                    self.filtered.get_or_insert(offset);
                } else if self.network.is_none() && is_network_type(context, owner) {
                    self.network = Some(Source::Call {
                        offset,
                        owner: owner.to_owned(),
                    });
                }
            }
            _ => {}
        }
    }

    fn finding(self, context: &Context, method: &MethodRef) -> Option<Finding> {
        let (created_at, created_type) = self.created?;
        let read_at = self.read?;
        let custom_stream = created_type != OBJECT_INPUT_STREAM;

        let severity = if self.filtered.is_some() || custom_stream {
            Severity::Notice
        } else if self.network.is_some() {
            Severity::Critical
        } else {
            Severity::Warning
        };
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
        match &self.network {
            Some(Source::Parameter(param)) => evidence.push(step(
                format!("Receives network data as a parameter of type {param}"),
                0,
            )),
            Some(Source::Call { offset, owner }) => {
                evidence.push(step(format!("Reads network data through {owner}"), *offset))
            }
            None => {}
        }
        evidence.push(step(format!("Creates {created_type}"), created_at));
        if let Some(offset) = self.filtered {
            evidence.push(step(
                "Installs an ObjectInputFilter that limits the classes it accepts".to_owned(),
                offset,
            ));
        } else if custom_stream {
            evidence.push(step(
                format!("{created_type} extends ObjectInputStream and may restrict the classes it resolves"),
                created_at,
            ));
        }
        evidence.push(step(
            "Calls readObject, which instantiates any serializable class the data names".to_owned(),
            read_at,
        ));

        Some(Finding {
            rule_id: RULE_ID.to_owned(),
            severity,
            title: title.to_owned(),
            location: context.location(method, read_at),
            evidence,
        })
    }
}

fn is_object_input_stream(context: &Context, name: &str) -> bool {
    context.hierarchy.extends_any(name, &[OBJECT_INPUT_STREAM])
}

fn is_network_type(context: &Context, name: &str) -> bool {
    context.hierarchy.extends_any(name, NETWORK_TYPES)
}

/// Internal names of the object types among a method descriptor's parameters.
fn parameter_types(descriptor: &str) -> Vec<String> {
    let params = descriptor
        .strip_prefix('(')
        .and_then(|rest| rest.split_once(')'))
        .map_or("", |(params, _)| params);
    let mut types = Vec::new();
    let mut rest = params;
    while let Some(start) = rest.find('L') {
        let after = &rest[start + 1..];
        let Some(end) = after.find(';') else { break };
        types.push(after[..end].to_owned());
        rest = &after[end + 1..];
    }
    types
}

#[cfg(test)]
mod tests {
    use super::parameter_types;

    #[test]
    fn reads_object_parameter_types() {
        assert_eq!(
            parameter_types("(ILio/netty/buffer/ByteBuf;[Ljava/lang/String;J)V"),
            vec!["io/netty/buffer/ByteBuf", "java/lang/String"]
        );
        assert!(parameter_types("()V").is_empty());
        assert!(parameter_types("garbage").is_empty());
    }
}
