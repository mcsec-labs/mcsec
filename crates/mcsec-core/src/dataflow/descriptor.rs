//! Parsing JVM method descriptors into the shapes the engine needs.

/// One parameter or return type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JvmType {
    /// Long and double take two stack and local slots.
    pub wide: bool,
    /// Internal name for object types (`java/lang/String`), the descriptor
    /// for array types (`[B`), and `None` for primitives.
    pub reference: Option<String>,
}

/// A parsed method descriptor such as `(ILjava/lang/String;)V`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodType {
    pub params: Vec<JvmType>,
    /// `None` for `void`.
    pub returns: Option<JvmType>,
}

impl MethodType {
    /// Parses a method descriptor. Malformed parts end the parameter list
    /// early instead of failing, since a crafted class can carry garbage.
    pub fn parse(descriptor: &str) -> Self {
        let Some(rest) = descriptor.strip_prefix('(') else {
            return Self {
                params: Vec::new(),
                returns: None,
            };
        };
        let (params_part, return_part) = rest.split_once(')').unwrap_or((rest, "V"));
        let mut params = Vec::new();
        let mut cursor = params_part;
        while !cursor.is_empty() {
            match parse_type(cursor) {
                Some((jvm_type, next)) => {
                    params.push(jvm_type);
                    cursor = next;
                }
                None => break,
            }
        }
        let returns = match return_part {
            "V" => None,
            other => parse_type(other).map(|(jvm_type, _)| jvm_type),
        };
        Self { params, returns }
    }
}

/// The type of a field descriptor such as `J` or `Ljava/lang/String;`.
pub fn field_type(descriptor: &str) -> Option<JvmType> {
    parse_type(descriptor).map(|(jvm_type, _)| jvm_type)
}

fn parse_type(input: &str) -> Option<(JvmType, &str)> {
    let first = input.chars().next()?;
    match first {
        'J' | 'D' => Some((
            JvmType {
                wide: true,
                reference: None,
            },
            &input[1..],
        )),
        'B' | 'C' | 'F' | 'I' | 'S' | 'Z' => Some((
            JvmType {
                wide: false,
                reference: None,
            },
            &input[1..],
        )),
        'L' => {
            let end = input.find(';')?;
            Some((
                JvmType {
                    wide: false,
                    reference: Some(input[1..end].to_owned()),
                },
                &input[end + 1..],
            ))
        }
        '[' => {
            let dims = input.chars().take_while(|&c| c == '[').count();
            let (_, rest) = parse_type(&input[dims..])?;
            let consumed = input.len() - rest.len();
            Some((
                JvmType {
                    wide: false,
                    reference: Some(input[..consumed].to_owned()),
                },
                rest,
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mixed_parameters() {
        let parsed = MethodType::parse(
            "(IJ[BLio/netty/buffer/ByteBuf;[[Ljava/lang/String;D)Ljava/lang/Object;",
        );
        let shapes: Vec<_> = parsed
            .params
            .iter()
            .map(|t| (t.wide, t.reference.as_deref()))
            .collect();
        assert_eq!(
            shapes,
            vec![
                (false, None),
                (true, None),
                (false, Some("[B")),
                (false, Some("io/netty/buffer/ByteBuf")),
                (false, Some("[[Ljava/lang/String;")),
                (true, None),
            ]
        );
        assert_eq!(
            parsed.returns.unwrap().reference.as_deref(),
            Some("java/lang/Object")
        );
    }

    #[test]
    fn tolerates_garbage() {
        assert!(MethodType::parse("").params.is_empty());
        assert!(MethodType::parse("(Lunterminated").params.is_empty());
        assert_eq!(MethodType::parse("(I?J)V").params.len(), 1);
        assert!(MethodType::parse("()V").returns.is_none());
    }
}
