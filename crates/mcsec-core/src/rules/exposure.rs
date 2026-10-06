//! Packet registrations, and which side of a connection each one lets send
//! data to the mod.
//!
//! Loaders register a packet through a call that names its payload class,
//! codec, or handler, such as NeoForge's `playToServer` or Fabric's
//! `registerGlobalReceiver`. One pass over the jar finds those calls and
//! marks every class and method they name with the side that sends the
//! packet. Packet data entering a marked method, or any method of a marked
//! class, carries a label for that side. The label follows the data like any
//! other, so a finding reads its exposure from the data that reaches it.

use std::collections::{HashMap, HashSet};

use super::flow::MethodKey;
use super::method_key;
use super::spec::MAX_SOURCES;
use crate::analysis::{ParsedArchive, ParsedClass};
use crate::class_file::{BootstrapMethod, Constant, ConstantPool, Member, Operand, op};
use crate::dataflow::{self, Known, Labels, MethodType, Policy, Value};
use crate::finding::{DataOrigin, Exposure};

/// Data in a packet that players send to a server. The direction labels sit
/// just above the bits rule sources can take, so the two never overlap.
pub(crate) const FROM_PLAYERS: Labels = Labels(1 << MAX_SOURCES);
/// Data in a packet that a server sends to players.
pub(crate) const FROM_SERVERS: Labels = Labels(1 << (MAX_SOURCES + 1));
/// Data in a packet either side can send.
pub(crate) const FROM_EITHER: Labels = Labels(FROM_PLAYERS.0 | FROM_SERVERS.0);

/// How a registration call says which side sends the packet.
#[derive(Debug, Clone, Copy)]
enum Direction {
    Fixed(Labels),
    /// Named by a constant among the call's inputs, such as `Side.C2S` or
    /// `NetworkDirection.PLAY_TO_SERVER`, or this when none is.
    Named(Labels),
}

/// Calls that register a packet.
struct Api {
    owner: &'static str,
    methods: &'static [&'static str],
    direction: Direction,
}

const APIS: &[Api] = &[
    // Forge 1.7 to 1.12 decodes every registered message on whichever side
    // receives it, whatever side its handler is registered for.
    Api {
        owner: "cpw/mods/fml/common/network/simpleimpl/SimpleNetworkWrapper",
        methods: &["registerMessage"],
        direction: Direction::Fixed(FROM_EITHER),
    },
    Api {
        owner: "net/minecraftforge/fml/common/network/simpleimpl/SimpleNetworkWrapper",
        methods: &["registerMessage"],
        direction: Direction::Fixed(FROM_EITHER),
    },
    // Forge 1.13 and later decode a message registered without a direction
    // on both sides.
    Api {
        owner: "net/minecraftforge/fml/network/simple/SimpleChannel",
        methods: &["registerMessage", "messageBuilder"],
        direction: Direction::Named(FROM_EITHER),
    },
    Api {
        owner: "net/minecraftforge/network/simple/SimpleChannel",
        methods: &["registerMessage", "messageBuilder"],
        direction: Direction::Named(FROM_EITHER),
    },
    Api {
        owner: "net/minecraftforge/network/SimpleChannel",
        methods: &["messageBuilder"],
        direction: Direction::Named(FROM_EITHER),
    },
    // NeoForge 1.20.4.
    Api {
        owner: "net/neoforged/neoforge/network/registration/IPayloadRegistrar",
        methods: &["play", "configuration", "common"],
        direction: Direction::Fixed(FROM_EITHER),
    },
    // NeoForge 1.20.5 and later.
    Api {
        owner: "net/neoforged/neoforge/network/registration/PayloadRegistrar",
        methods: &["playToServer", "configurationToServer", "commonToServer"],
        direction: Direction::Fixed(FROM_PLAYERS),
    },
    Api {
        owner: "net/neoforged/neoforge/network/registration/PayloadRegistrar",
        methods: &["playToClient", "configurationToClient", "commonToClient"],
        direction: Direction::Fixed(FROM_SERVERS),
    },
    Api {
        owner: "net/neoforged/neoforge/network/registration/PayloadRegistrar",
        methods: &[
            "playBidirectional",
            "configurationBidirectional",
            "commonBidirectional",
        ],
        direction: Direction::Fixed(FROM_EITHER),
    },
    // Fabric API.
    Api {
        owner: "net/fabricmc/fabric/api/networking/v1/ServerPlayNetworking",
        methods: &["registerGlobalReceiver", "registerReceiver"],
        direction: Direction::Fixed(FROM_PLAYERS),
    },
    Api {
        owner: "net/fabricmc/fabric/api/networking/v1/ServerConfigurationNetworking",
        methods: &["registerGlobalReceiver", "registerReceiver"],
        direction: Direction::Fixed(FROM_PLAYERS),
    },
    Api {
        owner: "net/fabricmc/fabric/api/networking/v1/ServerLoginNetworking",
        methods: &["registerGlobalReceiver", "registerReceiver"],
        direction: Direction::Fixed(FROM_PLAYERS),
    },
    Api {
        owner: "net/fabricmc/fabric/api/client/networking/v1/ClientPlayNetworking",
        methods: &["registerGlobalReceiver", "registerReceiver"],
        direction: Direction::Fixed(FROM_SERVERS),
    },
    Api {
        owner: "net/fabricmc/fabric/api/client/networking/v1/ClientConfigurationNetworking",
        methods: &["registerGlobalReceiver", "registerReceiver"],
        direction: Direction::Fixed(FROM_SERVERS),
    },
    Api {
        owner: "net/fabricmc/fabric/api/client/networking/v1/ClientLoginNetworking",
        methods: &["registerGlobalReceiver", "registerReceiver"],
        direction: Direction::Fixed(FROM_SERVERS),
    },
    // The registry is picked by an accessor such as playC2S() on the
    // receiver.
    Api {
        owner: "net/fabricmc/fabric/api/networking/v1/PayloadTypeRegistry",
        methods: &["register"],
        direction: Direction::Named(FROM_EITHER),
    },
    // Fabric API for 1.14 to 1.16.
    Api {
        owner: "net/fabricmc/fabric/api/network/ServerSidePacketRegistry",
        methods: &["register"],
        direction: Direction::Fixed(FROM_PLAYERS),
    },
    Api {
        owner: "net/fabricmc/fabric/api/network/ClientSidePacketRegistry",
        methods: &["register"],
        direction: Direction::Fixed(FROM_SERVERS),
    },
    // Architectury.
    Api {
        owner: "dev/architectury/networking/NetworkManager",
        methods: &["registerReceiver"],
        direction: Direction::Named(FROM_EITHER),
    },
    Api {
        owner: "dev/architectury/networking/NetworkManager",
        methods: &["registerS2CPayloadType"],
        direction: Direction::Fixed(FROM_SERVERS),
    },
    Api {
        owner: "me/shedaniel/architectury/networking/NetworkManager",
        methods: &["registerReceiver"],
        direction: Direction::Named(FROM_EITHER),
    },
    Api {
        owner: "dev/architectury/networking/NetworkChannel",
        methods: &["register"],
        direction: Direction::Fixed(FROM_EITHER),
    },
    Api {
        owner: "me/shedaniel/architectury/networking/NetworkChannel",
        methods: &["register"],
        direction: Direction::Fixed(FROM_EITHER),
    },
];

/// Constant names that say a packet goes from a player to a server, matched
/// against the part after the last dot of a static field or accessor.
const TO_SERVER: &[&str] = &[
    "C2S",
    "PLAY_TO_SERVER",
    "LOGIN_TO_SERVER",
    "SERVERBOUND",
    "playC2S",
    "configurationC2S",
];

/// Constant names that say a packet goes from a server to a player.
const TO_CLIENT: &[&str] = &[
    "S2C",
    "PLAY_TO_CLIENT",
    "LOGIN_TO_CLIENT",
    "CLIENTBOUND",
    "playS2C",
    "configurationS2C",
];

/// Events that deliver a packet to the methods subscribed to them. A method
/// taking one of these as a parameter handles packets from that side.
const EVENTS: &[(&str, Labels)] = &[
    (
        "cpw/mods/fml/common/network/FMLNetworkEvent$ServerCustomPacketEvent",
        FROM_PLAYERS,
    ),
    (
        "cpw/mods/fml/common/network/FMLNetworkEvent$ClientCustomPacketEvent",
        FROM_SERVERS,
    ),
    (
        "net/minecraftforge/fml/common/network/FMLNetworkEvent$ServerCustomPacketEvent",
        FROM_PLAYERS,
    ),
    (
        "net/minecraftforge/fml/common/network/FMLNetworkEvent$ClientCustomPacketEvent",
        FROM_SERVERS,
    ),
    // Forge 1.13 to 1.20.1 names these events by the side that sent the
    // packet, so the client's event is the one a server receives.
    (
        "net/minecraftforge/fml/network/NetworkEvent$ClientCustomPayloadEvent",
        FROM_PLAYERS,
    ),
    (
        "net/minecraftforge/fml/network/NetworkEvent$ServerCustomPayloadEvent",
        FROM_SERVERS,
    ),
    (
        "net/minecraftforge/network/NetworkEvent$ClientCustomPayloadEvent",
        FROM_PLAYERS,
    ),
    (
        "net/minecraftforge/network/NetworkEvent$ServerCustomPayloadEvent",
        FROM_SERVERS,
    ),
    (
        "net/minecraftforge/event/network/CustomPayloadEvent",
        FROM_EITHER,
    ),
];

/// The classes and methods packet registrations name, with the sides that
/// send their packets.
#[derive(Debug, Default)]
pub(crate) struct Registrations {
    classes: HashMap<String, Labels>,
    methods: HashMap<MethodKey, Labels>,
}

impl Registrations {
    pub fn build(root: &ParsedArchive) -> Self {
        let mut out = Self::default();
        let events: Vec<(String, Labels)> = EVENTS
            .iter()
            .map(|(event, sides)| (format!("L{event};"), *sides))
            .collect();
        for archive in root.walk() {
            for parsed in &archive.classes {
                let pool = &parsed.class.constant_pool;
                for method in &parsed.class.methods {
                    let Ok(descriptor) = method.descriptor(pool) else {
                        continue;
                    };
                    for (event, sides) in &events {
                        if descriptor.contains(event.as_str())
                            && let Ok(name) = method.name(pool)
                        {
                            out.mark_method(method_key(&parsed.name, &name, &descriptor), *sides);
                        }
                    }
                }
            }
        }

        // Each round analyzes the methods calling a target found in the
        // round before, starting from the registration APIs.
        let mut targets = Targets {
            owners: APIS.iter().map(|api| api.owner.to_owned()).collect(),
            wrappers: HashMap::new(),
        };
        let mut fresh: Option<HashSet<MethodKey>> = None;
        for _ in 0..MAX_WRAPPER_DEPTH {
            let mut found: HashSet<MethodKey> = HashSet::new();
            for archive in root.walk() {
                for parsed in &archive.classes {
                    out.scan_class(parsed, &mut targets, fresh.as_ref(), &mut found);
                }
            }
            if found.is_empty() {
                break;
            }
            fresh = Some(found);
        }
        out
    }

    /// Analyzes the methods of one class that call a registration target,
    /// marking what each call names. A method passing its own parameters
    /// into a registration becomes a wrapper, added to `targets` and
    /// `found`. With `fresh`, only calls to those wrappers are looked at.
    fn scan_class(
        &mut self,
        parsed: &ParsedClass,
        targets: &mut Targets,
        fresh: Option<&HashSet<MethodKey>>,
        found: &mut HashSet<MethodKey>,
    ) {
        let pool = &parsed.class.constant_pool;
        // Only classes that name a target's class can call one.
        let names_target = pool.iter().any(|(index, constant)| {
            matches!(constant, Constant::Class { .. })
                && pool
                    .class_name(index)
                    .is_ok_and(|name| targets.owners.contains(&*name))
        });
        if !names_target {
            return;
        }
        let bootstraps = parsed.class.bootstrap_methods().unwrap_or_default();
        for method in &parsed.class.methods {
            let (Ok(name), Ok(descriptor)) = (method.name(pool), method.descriptor(pool)) else {
                continue;
            };
            if !calls_target(pool, method, targets, fresh) {
                continue;
            }
            let key = method_key(&parsed.name, &name, &descriptor);
            let mut wrapped: Option<Wrapper> = None;
            dataflow::analyze(&parsed.class, method, &NoSources, &mut |site, frame| {
                let ins = site.instruction;
                let index = match (ins.opcode, &ins.operand) {
                    (
                        op::INVOKEVIRTUAL
                        | op::INVOKESTATIC
                        | op::INVOKEINTERFACE
                        | op::INVOKESPECIAL,
                        Operand::Constant(index) | Operand::InvokeInterface { index, .. },
                    ) => *index,
                    _ => return,
                };
                let Ok(target) = site.pool.member_ref(index) else {
                    return;
                };
                let Some((direction, params)) =
                    targets.find(&target.class_name, &target.name, &target.descriptor, fresh)
                else {
                    return;
                };
                let count = MethodType::parse(&target.descriptor).params.len();
                let arguments: Vec<&Value> =
                    (0..count).rev().filter_map(|d| frame.peek(d)).collect();
                let receiver = (ins.opcode != op::INVOKESTATIC)
                    .then(|| frame.peek(count))
                    .flatten();
                let named = receiver
                    .into_iter()
                    .chain(arguments.iter().copied())
                    .fold(Labels::default(), |acc, v| Labels(acc.0 | named(v).0));
                let direction = match direction {
                    Direction::Named(_) if !named.is_empty() => Direction::Fixed(named),
                    other => other,
                };
                let (Direction::Fixed(sides) | Direction::Named(sides)) = direction;
                // The receiver is the channel or registrar, often a field of
                // the mod's main class, so it names nothing.
                for (position, value) in arguments.into_iter().enumerate() {
                    if params & (1 << position.min(63)) == 0 {
                        continue;
                    }
                    if value.params != 0 {
                        let wrapper = wrapped.get_or_insert(Wrapper {
                            direction,
                            params: 0,
                        });
                        wrapper.params |= value.params;
                    }
                    self.mark_value(site.pool, &bootstraps, value, sides);
                }
            });
            if let Some(wrapper) = wrapped {
                let known = targets.wrappers.get(&key).map(|w| w.params);
                if known.is_none_or(|params| params | wrapper.params != params) {
                    targets.owners.insert(parsed.name.clone());
                    targets.wrappers.insert(key.clone(), wrapper);
                    found.insert(key);
                }
            }
        }
    }

    fn mark_class(&mut self, class: &str, sides: Labels) {
        self.classes.entry(class.to_owned()).or_default().0 |= sides.0;
    }

    fn mark_method(&mut self, key: MethodKey, sides: Labels) {
        self.methods.entry(key).or_default().0 |= sides.0;
    }

    /// Marks what one argument of a registration call names. A class
    /// constant names a payload or handler class, a static field or a field
    /// read names the class holding a codec or payload type, a new object
    /// names its class, and a lambda or method reference names the method it
    /// runs and the classes of that method's parameters.
    fn mark_value(
        &mut self,
        pool: &ConstantPool,
        bootstraps: &[BootstrapMethod],
        value: &Value,
        sides: Labels,
    ) {
        match &value.known {
            Some(Known::Class(class)) => self.mark_class(class, sides),
            Some(Known::Lambda(index)) => {
                if let Some(lambda) = dataflow::lambda_target(pool, bootstraps, *index) {
                    for param in MethodType::parse(&lambda.descriptor).params {
                        if let Some(class) = param.reference.filter(|c| !c.starts_with('[')) {
                            self.mark_class(&class, sides);
                        }
                    }
                    self.mark_method(
                        method_key(&lambda.owner, &lambda.name, &lambda.descriptor),
                        sides,
                    );
                }
            }
            _ => {}
        }
        if let Some((owner, _)) = value.field.as_deref().and_then(|f| f.rsplit_once('.')) {
            self.mark_class(owner, sides);
        }
        if let Some(alloc) = value.alloc.as_ref().filter(|a| a.made) {
            self.mark_class(&alloc.class, sides);
        }
    }

    /// The sides whose packets reach `name` in `class`, from a registration
    /// naming the method or its class.
    pub fn sides(&self, class: &str, name: &str, descriptor: &str) -> Labels {
        let by_class = self.classes.get(class).copied().unwrap_or_default();
        let by_method = self
            .methods
            .get(&method_key(class, name, descriptor))
            .copied()
            .unwrap_or_default();
        Labels(by_class.0 | by_method.0)
    }
}

/// Bound on how deeply registration wrappers nest, each level a method
/// passing its parameters on to the next.
const MAX_WRAPPER_DEPTH: usize = 4;

/// A method that passes some of its parameters into a registration, so a
/// call to it registers what those arguments name.
#[derive(Debug, Clone, Copy)]
struct Wrapper {
    direction: Direction,
    /// The method's declared parameters that reach the registration.
    params: u64,
}

/// What counts as a registration call.
struct Targets {
    /// Classes declaring an API or a wrapper, for skipping classes that
    /// cannot call one.
    owners: HashSet<String>,
    wrappers: HashMap<MethodKey, Wrapper>,
}

impl Targets {
    /// The direction of a call to `owner.name`, and the arguments that name
    /// what it registers, one bit per argument. With `fresh`, only calls to
    /// those wrappers count.
    fn find(
        &self,
        owner: &str,
        name: &str,
        descriptor: &str,
        fresh: Option<&HashSet<MethodKey>>,
    ) -> Option<(Direction, u64)> {
        if !self.owners.contains(owner) {
            return None;
        }
        let key = method_key(owner, name, descriptor);
        if let Some(fresh) = fresh {
            return fresh
                .contains(&key)
                .then(|| self.wrappers.get(&key))
                .flatten()
                .map(|w| (w.direction, w.params));
        }
        if let Some(api) = APIS
            .iter()
            .find(|api| api.owner == owner && api.methods.contains(&name))
        {
            return Some((api.direction, u64::MAX));
        }
        self.wrappers.get(&key).map(|w| (w.direction, w.params))
    }
}

/// True when the method's bytecode calls a registration target, so only
/// those methods need the data flow that reads the call's inputs.
fn calls_target(
    pool: &ConstantPool,
    method: &Member,
    targets: &Targets,
    fresh: Option<&HashSet<MethodKey>>,
) -> bool {
    let Ok(Some(code)) = method.code(pool) else {
        return false;
    };
    code.instructions().flatten().any(|ins| {
        let index = match (ins.opcode, &ins.operand) {
            (
                op::INVOKEVIRTUAL | op::INVOKESTATIC | op::INVOKEINTERFACE | op::INVOKESPECIAL,
                Operand::Constant(index) | Operand::InvokeInterface { index, .. },
            ) => *index,
            _ => return false,
        };
        pool.member_ref(index).is_ok_and(|target| {
            targets
                .find(&target.class_name, &target.name, &target.descriptor, fresh)
                .is_some()
        })
    })
}

/// The sides a constant among a registration's inputs names.
fn named(value: &Value) -> Labels {
    let name = match &value.known {
        Some(Known::Static(name) | Known::Call(name)) => name,
        _ => return Labels::default(),
    };
    let last = name.rsplit('.').next().unwrap_or_default();
    if TO_SERVER.contains(&last) {
        FROM_PLAYERS
    } else if TO_CLIENT.contains(&last) {
        FROM_SERVERS
    } else {
        Labels::default()
    }
}

/// Who can supply data with `labels` from `origin`. Network data that no
/// recognized registration reaches gets none, since the mod may register or
/// dispatch its packets in a way the scanner does not know.
pub(crate) fn exposure(origin: DataOrigin, labels: Labels) -> Option<Exposure> {
    match origin {
        DataOrigin::LocalFile => Some(Exposure::LocalUser),
        DataOrigin::Network if labels.0 & FROM_PLAYERS.0 != 0 => Some(Exposure::AnyPlayer),
        DataOrigin::Network if labels.0 & FROM_SERVERS.0 != 0 => Some(Exposure::AnyServer),
        _ => None,
    }
}

/// A policy with no sources, for finding the constants and lambdas passed to
/// registration calls.
struct NoSources;

impl Policy for NoSources {
    fn parameter(&self, _index: Option<usize>, _ty: &str) -> Option<(Labels, String)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::spec;

    #[test]
    fn direction_labels_sit_above_every_source() {
        let highest_source = Labels(1 << (MAX_SOURCES - 1));
        assert_eq!(highest_source.0 & FROM_EITHER.0, 0);
        assert!(FROM_PLAYERS.0.min(FROM_SERVERS.0) > highest_source.0);
        for rule in spec::embedded() {
            for source in &rule.sources {
                assert_eq!(source.label.0 & FROM_EITHER.0, 0, "source {}", source.id);
            }
        }
    }
}
