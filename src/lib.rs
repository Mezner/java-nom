use std::path::PathBuf;
use std::io::BufRead;
use std::boxed::Box;
use std::error::Error;
use std::fmt::{Display, Debug};

#[derive(Default)]
pub struct ParseError;

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "A parsing error occurred.")
    }
}

impl Debug for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <ParseError as std::fmt::Display>::fmt(self, f)
    }
}

impl std::error::Error for ParseError { }

pub fn read_lines(path: &PathBuf) -> Result<Vec<BasicType>, Box<dyn Error>> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.lines() {
        match parsers::basic_type(&line?) {
            Ok((_, m)) => {
                match BasicType::from_str(m) {
                    Ok(t) => {
                        lines.push(t);
                    },
                    Err(_) => return Err(ParseError::default().into())
                }
            }
            Err(_) => return Err(ParseError::default().into())
        }
    }
    Ok(lines)
}

#[derive(Clone, Debug)]
pub enum BasicType {
    Byte,
    Short,
    Char,
    Int,
    Long,
    Float,
    Double,
    Boolean,
}

impl BasicType {
    fn from_str(i: &str) -> Result<BasicType, Box<dyn Error>>{
        match i {
            "byte" => Ok(BasicType::Byte),
            "short" => Ok(BasicType::Short),
            "char" => Ok(BasicType::Char),
            "int" => Ok(BasicType::Int),
            "long" => Ok(BasicType::Long),
            "float" => Ok(BasicType::Float),
            "double" => Ok(BasicType::Double),
            "boolean" => Ok(BasicType::Boolean),
            _ => Err(ParseError::default().into())
        }
    }
}

impl Display for BasicType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            BasicType::Byte => write!(f, "byte"),
            BasicType::Short => write!(f, "short"),
            BasicType::Char => write!(f, "char"),
            BasicType::Int => write!(f, "int"),
            BasicType::Long => write!(f, "long"),
            BasicType::Float => write!(f, "float"),
            BasicType::Double => write!(f, "double"),
            BasicType::Boolean => write!(f, "boolean"),
        }
    }
}

#[derive(Clone, Debug)]
pub enum AssignmentOperator {
    Equals,
    PlusEquals,
    MinusEquals,
    TimesEquals,
    DivideEquals,
    AndEquals,
    OrEquals,
    XorEquals,
    ModuloEquals,
    LeftShiftEquals,
    RightShiftSignedEquals,
    RightShiftUnsignedEquals,
}

impl AssignmentOperator {
    fn from_str(i: &str) -> Result<AssignmentOperator, Box<dyn Error>> {
        match i {
            "=" => Ok(AssignmentOperator::Equals),
            "+=" => Ok(AssignmentOperator::PlusEquals),
            "-=" => Ok(AssignmentOperator::MinusEquals),
            "*=" => Ok(AssignmentOperator::TimesEquals),
            "/=" => Ok(AssignmentOperator::DivideEquals),
            "&=" => Ok(AssignmentOperator::AndEquals),
            "|=" => Ok(AssignmentOperator::OrEquals),
            "^=" => Ok(AssignmentOperator::XorEquals),
            "%=" => Ok(AssignmentOperator::ModuloEquals),
            "<<=" => Ok(AssignmentOperator::LeftShiftEquals),
            ">>=" => Ok(AssignmentOperator::RightShiftSignedEquals),
            ">>>=" => Ok(AssignmentOperator::RightShiftUnsignedEquals),
            _ => Err(ParseError::default().into())
        }
    }
}

impl Display for AssignmentOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            AssignmentOperator::Equals => write!(f, "="),
            AssignmentOperator::PlusEquals => write!(f, "+="),
            AssignmentOperator::MinusEquals => write!(f, "-="),
            AssignmentOperator::TimesEquals => write!(f, "*="),
            AssignmentOperator::DivideEquals => write!(f, "/="),
            AssignmentOperator::AndEquals => write!(f, "&="),
            AssignmentOperator::OrEquals => write!(f, "|="),
            AssignmentOperator::XorEquals => write!(f, "^="),
            AssignmentOperator::ModuloEquals => write!(f, "%="),
            AssignmentOperator::LeftShiftEquals => write!(f, "<<="),
            AssignmentOperator::RightShiftSignedEquals => write!(f, ">>="),
            AssignmentOperator::RightShiftUnsignedEquals => write!(f, ">>>="),
        }
    }
}

#[derive(Clone, Debug)]
pub enum InfixOperator {
    Or,
    And,
    SingleOr,
    Xor,
    SingleAnd,
    Equals,
    NotEquals,
    LessThan,
    GreaterThan,
    LessThanOrEqual,
    GreaterThanOrEqual,
    ShiftLeft,
    ShiftRightSigned,
    ShiftRightUnsigned,
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
}

impl InfixOperator {
    fn from_str(i: &str) -> Result<InfixOperator, Box<dyn Error>> {
        match i {
            "||" => Ok(InfixOperator::Or),
            "&&" => Ok(InfixOperator::And),
            "|" => Ok(InfixOperator::SingleOr),
            "^" => Ok(InfixOperator::Xor),
            "&" => Ok(InfixOperator::SingleAnd),
            "==" => Ok(InfixOperator::Equals),
            "!=" => Ok(InfixOperator::NotEquals),
            "<" => Ok(InfixOperator::LessThan),
            ">" => Ok(InfixOperator::GreaterThan),
            "<=" => Ok(InfixOperator::LessThanOrEqual),
            ">=" => Ok(InfixOperator::GreaterThanOrEqual),
            "<<" => Ok(InfixOperator::ShiftLeft),
            ">>" => Ok(InfixOperator::ShiftRightSigned),
            ">>>" => Ok(InfixOperator::ShiftRightUnsigned),
            "+" => Ok(InfixOperator::Add),
            "-" => Ok(InfixOperator::Subtract),
            "*" => Ok(InfixOperator::Multiply),
            "/" => Ok(InfixOperator::Divide),
            "%" => Ok(InfixOperator::Modulo),
            _ => Err(ParseError::default().into())
        }
    }
}

pub(self) mod parsers {
    fn not_whitespace(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::is_not(" \t")(i)
    }

    fn escaped_space(i: &str) -> nom::IResult<&str, &str> {
        nom::combinator::value(" ", nom::bytes::complete::tag("040"))(i)
    }

    fn escaped_backslash(i: &str) -> nom::IResult<&str, &str> {
        nom::combinator::recognize(nom::character::complete::char('\\'))(i)
    }

    fn transform_escaped(i: &str) -> nom::IResult<&str, String> {
        nom::bytes::complete::escaped_transform(nom::bytes::complete::is_not("\\"), '\\', nom::branch::alt((escaped_backslash, escaped_space)))(i)
    }

    fn mount_opts(i: &str) -> nom::IResult<&str, Vec<String>> {
        nom::multi::separated_list(
            nom::character::complete::char(','),
            nom::combinator::map_parser(
                nom::bytes::complete::is_not(", \t"),
                transform_escaped
            )
        )(i)
    }

    fn basic_type_byte(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("byte")(i)
    }

    fn basic_type_short(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("short")(i)
    }

    fn basic_type_char(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("char")(i)
    }

    fn basic_type_int(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("int")(i)
    }

    fn basic_type_long(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("long")(i)
    }

    fn basic_type_float(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("float")(i)
    }

    fn basic_type_double(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("double")(i)
    }

    fn basic_type_boolean(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("boolean")(i)
    }

    //TODO: Remove pub later.
    pub fn basic_type(i: &str) -> nom::IResult<&str, &str> {
        nom::branch::alt((
            basic_type_byte,
            basic_type_short,
            basic_type_char,
            basic_type_int,
            basic_type_long,
            basic_type_float,
            basic_type_double,
            basic_type_boolean
        ))(i)
    }

    fn assignment_operator_equals(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("=")(i)
    }

    fn assignment_operator_plus_equals(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("+=")(i)
    }


    fn assignment_operator_minus_equals(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("-=")(i)
    }


    fn assignment_operator_times_equals(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("*=")(i)
    }


    fn assignment_operator_divide_equals(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("/=")(i)
    }


    fn assignment_operator_and_equals(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("&=")(i)
    }


    fn assignment_operator_or_equals(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("|=")(i)
    }


    fn assignment_operator_xor_equals(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("^=")(i)
    }


    fn assignment_operator_modulo_equals(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("%=")(i)
    }


    fn assignment_operator_left_shift_equals(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("<<=")(i)
    }


    fn assignment_operator_right_shift_signed_equals(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag(">>=")(i)
    }


    fn assignment_operator_right_shift_unsigned_equals(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag(">>>=")(i)
    }

    pub fn assignment_operator(i: &str) -> nom::IResult<&str, &str> {
        nom::branch::alt((
            assignment_operator_equals,
            assignment_operator_plus_equals,
            assignment_operator_minus_equals,
            assignment_operator_times_equals,
            assignment_operator_divide_equals,
            assignment_operator_and_equals,
            assignment_operator_or_equals,
            assignment_operator_xor_equals,
            assignment_operator_modulo_equals,
            assignment_operator_left_shift_equals,
            assignment_operator_right_shift_signed_equals,
            assignment_operator_right_shift_unsigned_equals
        ))(i)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_not_whitespace() {
            assert_eq!(not_whitespace("abcd efg"), Ok((" efg", "abcd")));
            assert_eq!(not_whitespace("abcd\tefg"), Ok(("\tefg", "abcd")));
            assert_eq!(not_whitespace(" abcdefg"), Err(nom::Err::Error((" abcdefg", nom::error::ErrorKind::IsNot))));
        }

        #[test]
        fn test_escaped_backslash() {
            assert_eq!(escaped_backslash("\\"), Ok(("", "\\")));
            assert_eq!(escaped_backslash("not a backslash"), Err(nom::Err::Error(("not a backslash", nom::error::ErrorKind::Char))));
        }

        #[test]
        fn test_transform_escaped() {
            assert_eq!(transform_escaped("\\bad"), Err(nom::Err::Error(("bad", nom::error::ErrorKind::Tag))));
            assert_eq!(transform_escaped("abc\\040def\\\\g\\040h"), Ok(("", String::from("abc def\\g h"))));
        }

        #[test]
        fn test_mount_opts() {
            assert_eq!(mount_opts("a,bc,d\\040e"), Ok(("", vec!["a".to_string(), "bc".to_string(), "d e".to_string()])));
        }

        #[test]
        fn test_basic_type_byte() {
            assert_eq!(basic_type_byte("byte"), Ok(("", "byte")));
            assert_eq!(basic_type_byte("not byte"), Err(nom::Err::Error(("not byte", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_basic_type_short() {
            assert_eq!(basic_type_short("short"), Ok(("", "short")));
            assert_eq!(basic_type_short("not short"), Err(nom::Err::Error(("not short", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_basic_type_char() {
            assert_eq!(basic_type_char("char"), Ok(("", "char")));
            assert_eq!(basic_type_char("not char"), Err(nom::Err::Error(("not char", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_basic_type_int() {
            assert_eq!(basic_type_int("int"), Ok(("", "int")));
            assert_eq!(basic_type_int("not int"), Err(nom::Err::Error(("not int", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_basic_type_long() {
            assert_eq!(basic_type_long("long"), Ok(("", "long")));
            assert_eq!(basic_type_long("not long"), Err(nom::Err::Error(("not long", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_basic_type_float() {
            assert_eq!(basic_type_float("float"), Ok(("", "float")));
            assert_eq!(basic_type_float("not float"), Err(nom::Err::Error(("not float", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_basic_type_double() {
            assert_eq!(basic_type_double("double"), Ok(("", "double")));
            assert_eq!(basic_type_double("not double"), Err(nom::Err::Error(("not double", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_basic_type_boolean() {
            assert_eq!(basic_type_boolean("boolean"), Ok(("", "boolean")));
            assert_eq!(basic_type_boolean("not boolean"), Err(nom::Err::Error(("not boolean", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_basic_type() {
            assert_eq!(basic_type("byte"), Ok(("", "byte")));
            assert_eq!(basic_type("short"), Ok(("", "short")));
            assert_eq!(basic_type("somethingelse"), Err(nom::Err::Error(("somethingelse", nom::error::ErrorKind::Tag))));
            assert_eq!(basic_type("char"), Ok(("", "char")));
            assert_eq!(basic_type("int"), Ok(("", "int")));
            assert_eq!(basic_type("long"), Ok(("", "long")));
            assert_eq!(basic_type("float"), Ok(("", "float")));
            assert_eq!(basic_type("double"), Ok(("", "double")));
            assert_eq!(basic_type("boolean"), Ok(("", "boolean")));
        }

        #[test]
        fn test_assignment_operator() {
            assert_eq!(assignment_operator("="), Ok(("", "=")));
            assert_eq!(assignment_operator("+="), Ok(("", "+=")));
            assert_eq!(assignment_operator("somethingelse"), Err(nom::Err::Error(("somethingelse", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_assignment_operator_equals() {
            assert_eq!(assignment_operator_equals("="), Ok(("", "=")));
            assert_eq!(assignment_operator_equals("+="), Err(nom::Err::Error(("+=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_assignment_operator_plus_equals() {
            assert_eq!(assignment_operator_plus_equals("+="), Ok(("", "+=")));
            assert_eq!(assignment_operator_plus_equals("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_assignment_operator_minus_equals() {
            assert_eq!(assignment_operator_minus_equals("-="), Ok(("", "-=")));
            assert_eq!(assignment_operator_minus_equals("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_assignment_operator_times_equals() {
            assert_eq!(assignment_operator_times_equals("*="), Ok(("", "*=")));
            assert_eq!(assignment_operator_times_equals("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_assignment_operator_divide_equals() {
            assert_eq!(assignment_operator_divide_equals("/="), Ok(("", "/=")));
            assert_eq!(assignment_operator_divide_equals("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_assignment_operator_and_equals() {
            assert_eq!(assignment_operator_and_equals("&="), Ok(("", "&=")));
            assert_eq!(assignment_operator_and_equals("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_assignment_operator_or_equals() {
            assert_eq!(assignment_operator_or_equals("|="), Ok(("", "|=")));
            assert_eq!(assignment_operator_or_equals("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_assignment_operator_xor_equals() {
            assert_eq!(assignment_operator_xor_equals("^="), Ok(("", "^=")));
            assert_eq!(assignment_operator_xor_equals("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_assignment_operator_modulo_equals() {
            assert_eq!(assignment_operator_modulo_equals("%="), Ok(("", "%=")));
            assert_eq!(assignment_operator_modulo_equals("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_assignment_operator_left_shift_equals() {
            assert_eq!(assignment_operator_left_shift_equals("<<="), Ok(("", "<<=")));
            assert_eq!(assignment_operator_left_shift_equals("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_assignment_operator_right_shift_signed_equals() {
            assert_eq!(assignment_operator_right_shift_signed_equals(">>="), Ok(("", ">>=")));
            assert_eq!(assignment_operator_right_shift_signed_equals("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_assignment_operator_right_shift_unsigned_equals() {
            assert_eq!(assignment_operator_right_shift_unsigned_equals(">>>="), Ok(("", ">>>=")));
            assert_eq!(assignment_operator_right_shift_unsigned_equals("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }
    }
}