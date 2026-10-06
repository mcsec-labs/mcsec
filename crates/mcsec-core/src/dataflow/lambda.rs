//! Lambdas and method references. Both compile to an `invokedynamic` call
//! site whose bootstrap is `LambdaMetafactory`. The bootstrap's static
//! arguments name the method holding the body, and the values the call site
//! takes from the stack are the values the lambda captures, which the body
//! receives ahead of its own arguments.

use crate::class_file::{BootstrapMethod, Constant, ConstantPool};

use super::MethodType;

const REF_INVOKE_VIRTUAL: u8 = 5;
const REF_INVOKE_SPECIAL: u8 = 7;
const REF_INVOKE_INTERFACE: u8 = 9;

/// The method a lambda or method reference runs, and how the values it
/// captures line up with that method's parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LambdaTarget {
    pub owner: String,
    pub name: String,
    pub descriptor: String,
    /// The first captured value is the body's receiver, as for a lambda that
    /// uses `this` or a bound method reference such as `handler::accept`.
    pub captures_receiver: bool,
    /// The body is reached through a virtual or interface method, so an
    /// override in a subclass can run instead.
    pub dispatches: bool,
    /// How many values the call site captures.
    pub captured: usize,
}

impl LambdaTarget {
    /// The body's declared parameter that captured value `index` becomes,
    /// or `None` when it becomes the receiver.
    pub fn parameter(&self, index: usize) -> Option<usize> {
        if self.captures_receiver {
            index.checked_sub(1)
        } else {
            Some(index)
        }
    }
}

/// Resolves the `invokedynamic` call site at constant pool `index` to the
/// method its lambda runs. Returns `None` for call sites with any other
/// bootstrap, such as string concatenation, and for malformed constants.
pub fn lambda_target(
    pool: &ConstantPool,
    bootstraps: &[BootstrapMethod],
    index: u16,
) -> Option<LambdaTarget> {
    let &Constant::InvokeDynamic {
        bootstrap_method_index,
        name_and_type_index,
    } = pool.get(index)?
    else {
        return None;
    };
    let (_, site_descriptor) = pool.name_and_type(name_and_type_index).ok()?;
    let bootstrap = bootstraps.get(usize::from(bootstrap_method_index))?;
    let &Constant::MethodHandle {
        reference_index, ..
    } = pool.get(bootstrap.method_ref)?
    else {
        return None;
    };
    if pool.member_ref(reference_index).ok()?.class_name != "java/lang/invoke/LambdaMetafactory" {
        return None;
    }
    // metafactory and altMetafactory both take the body's handle as their
    // second static argument.
    let &Constant::MethodHandle {
        reference_kind,
        reference_index,
    } = pool.get(*bootstrap.arguments.get(1)?)?
    else {
        return None;
    };
    let body = pool.member_ref(reference_index).ok()?;
    let captured = MethodType::parse(&site_descriptor).params.len();
    Some(LambdaTarget {
        owner: body.class_name.into_owned(),
        name: body.name.into_owned(),
        descriptor: body.descriptor.into_owned(),
        captures_receiver: captured > 0
            && matches!(
                reference_kind,
                REF_INVOKE_VIRTUAL | REF_INVOKE_SPECIAL | REF_INVOKE_INTERFACE
            ),
        dispatches: matches!(reference_kind, REF_INVOKE_VIRTUAL | REF_INVOKE_INTERFACE),
        captured,
    })
}
