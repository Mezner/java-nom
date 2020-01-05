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

impl Display for InfixOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            InfixOperator::Or => write!(f, "||"),
            InfixOperator::And => write!(f, "&&"),
            InfixOperator::SingleOr => write!(f, "|"),
            InfixOperator::Xor => write!(f, "^"),
            InfixOperator::SingleAnd => write!(f, "&"),
            InfixOperator::Equals => write!(f, "=="),
            InfixOperator::NotEquals => write!(f, "!="),
            InfixOperator::LessThan => write!(f, "<"),
            InfixOperator::GreaterThan => write!(f, ">"),
            InfixOperator::LessThanOrEqual => write!(f, "<="),
            InfixOperator::GreaterThanOrEqual => write!(f, ">="),
            InfixOperator::ShiftLeft => write!(f, "<<"),
            InfixOperator::ShiftRightSigned => write!(f, ">>"),
            InfixOperator::ShiftRightUnsigned => write!(f, ">>>"),
            InfixOperator::Add => write!(f, "+"),
            InfixOperator::Subtract => write!(f, "-"),
            InfixOperator::Multiply => write!(f, "*"),
            InfixOperator::Divide => write!(f, "/"),
            InfixOperator::Modulo => write!(f, "%"),
        }
    }
}

#[derive(Clone, Debug)]
pub enum PrefixOperator {
    AddOne,
    MinusOne,
    Not,
    Compliment,
    Plus,
    Minus,
}

impl PrefixOperator {
    fn from_str(i: &str) -> Result<PrefixOperator, Box<dyn Error>> {
        match i {
            "++" => Ok(PrefixOperator::AddOne),
            "--" => Ok(PrefixOperator::MinusOne),
            "!" => Ok(PrefixOperator::Not),
            "~" => Ok(PrefixOperator::Compliment),
            "+" => Ok(PrefixOperator::Plus),
            "-" => Ok(PrefixOperator::Minus),
            _ => Err(ParseError::default().into())
        }
    }
}

impl Display for PrefixOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            PrefixOperator::AddOne => write!(f, "++"),
            PrefixOperator::MinusOne => write!(f, "--"),
            PrefixOperator::Not => write!(f, "!"),
            PrefixOperator::Compliment => write!(f, "~"),
            PrefixOperator::Plus => write!(f, "+"),
            PrefixOperator::Minus => write!(f, "-"),
        }
    }
}

#[derive(Clone, Debug)]
pub enum PostfixOperator {
    AddOne,
    MinusOne,
}

pub enum BooleanLiteral {
    True,
    False
}

impl BooleanLiteral {
    fn from_str(i: &str) -> Result<BooleanLiteral, Box<dyn Error>> {
        match i {
            "true" => Ok(BooleanLiteral::True),
            "false" => Ok(BooleanLiteral::False),
            _ => Err(ParseError::default().into()),
        }
    }
}

impl Display for BooleanLiteral {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            BooleanLiteral::True => write!(f, "true"),
            BooleanLiteral::False => write!(f, "false"),
        }
    }
}

pub(self) mod parsers {
    use nom::branch::alt;
    use nom::bytes::complete::{tag, take_while, take_while1};
    use nom::sequence::tuple;
    use nom::combinator::recognize;

    type ParseResult<'a> = nom::IResult<&'a str, &'a str>;

    fn not_whitespace(i: &str) -> ParseResult {
        nom::bytes::complete::is_not(" \t")(i)
    }

    fn escaped_space(i: &str) -> ParseResult {
        nom::combinator::value(" ", nom::bytes::complete::tag("040"))(i)
    }

    fn escaped_backslash(i: &str) -> ParseResult {
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

    fn basic_type_byte(i: &str) -> ParseResult {
        nom::bytes::complete::tag("byte")(i)
    }

    fn basic_type_short(i: &str) -> ParseResult {
        nom::bytes::complete::tag("short")(i)
    }

    fn basic_type_char(i: &str) -> ParseResult {
        nom::bytes::complete::tag("char")(i)
    }

    fn basic_type_int(i: &str) -> ParseResult {
        nom::bytes::complete::tag("int")(i)
    }

    fn basic_type_long(i: &str) -> ParseResult {
        nom::bytes::complete::tag("long")(i)
    }

    fn basic_type_float(i: &str) -> ParseResult {
        nom::bytes::complete::tag("float")(i)
    }

    fn basic_type_double(i: &str) -> ParseResult {
        nom::bytes::complete::tag("double")(i)
    }

    fn basic_type_boolean(i: &str) -> ParseResult {
        nom::bytes::complete::tag("boolean")(i)
    }

    //TODO: Remove pub later.
    pub fn basic_type(i: &str) -> ParseResult {
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

    fn assignment_operator_equals(i: &str) -> ParseResult {
        nom::bytes::complete::tag("=")(i)
    }

    fn assignment_operator_plus_equals(i: &str) -> ParseResult {
        nom::bytes::complete::tag("+=")(i)
    }

    fn assignment_operator_minus_equals(i: &str) -> ParseResult {
        nom::bytes::complete::tag("-=")(i)
    }

    fn assignment_operator_times_equals(i: &str) -> ParseResult {
        nom::bytes::complete::tag("*=")(i)
    }

    fn assignment_operator_divide_equals(i: &str) -> ParseResult {
        nom::bytes::complete::tag("/=")(i)
    }

    fn assignment_operator_and_equals(i: &str) -> ParseResult {
        nom::bytes::complete::tag("&=")(i)
    }

    fn assignment_operator_or_equals(i: &str) -> ParseResult {
        nom::bytes::complete::tag("|=")(i)
    }

    fn assignment_operator_xor_equals(i: &str) -> ParseResult {
        nom::bytes::complete::tag("^=")(i)
    }

    fn assignment_operator_modulo_equals(i: &str) -> ParseResult {
        nom::bytes::complete::tag("%=")(i)
    }

    fn assignment_operator_left_shift_equals(i: &str) -> ParseResult {
        nom::bytes::complete::tag("<<=")(i)
    }

    fn assignment_operator_right_shift_signed_equals(i: &str) -> ParseResult {
        nom::bytes::complete::tag(">>=")(i)
    }

    fn assignment_operator_right_shift_unsigned_equals(i: &str) -> ParseResult {
        nom::bytes::complete::tag(">>>=")(i)
    }

    pub fn assignment_operator(i: &str) -> ParseResult {
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

    fn infix_operator_or(i: &str) -> ParseResult {
        nom::bytes::complete::tag("||")(i)
    }

    fn infix_operator_and(i: &str) -> ParseResult {
        nom::bytes::complete::tag("&&")(i)
    }

    fn infix_operator_single_or(i: &str) -> ParseResult {
        nom::bytes::complete::tag("|")(i)
    }

    fn infix_operator_xor(i: &str) -> ParseResult {
        nom::bytes::complete::tag("^")(i)
    }

    fn infix_operator_single_and(i: &str) -> ParseResult {
        nom::bytes::complete::tag("&")(i)
    }

    fn infix_operator_equals(i: &str) -> ParseResult {
        nom::bytes::complete::tag("==")(i)
    }

    fn infix_operator_not_equals(i: &str) -> ParseResult {
        nom::bytes::complete::tag("!=")(i)
    }

    fn infix_operator_less_than(i: &str) -> ParseResult {
        nom::bytes::complete::tag("<")(i)
    }

    fn infix_operator_greater_than(i: &str) -> ParseResult {
        nom::bytes::complete::tag(">")(i)
    }

    fn infix_operator_less_than_or_equal(i: &str) -> ParseResult {
        nom::bytes::complete::tag("<=")(i)
    }

    fn infix_operator_greater_than_or_equal(i: &str) -> ParseResult {
        nom::bytes::complete::tag(">=")(i)
    }

    fn infix_operator_left_shift(i: &str) -> ParseResult {
        nom::bytes::complete::tag("<<")(i)
    }

    fn infix_operator_right_shift_signed(i: &str) -> ParseResult {
        nom::bytes::complete::tag(">>")(i)
    }

    fn infix_operator_right_shift_unsigned(i: &str) -> ParseResult {
        nom::bytes::complete::tag(">>>")(i)
    }

    fn infix_operator_add(i: &str) -> ParseResult {
        nom::bytes::complete::tag("+")(i)
    }

    fn infix_operator_subtract(i: &str) -> ParseResult {
        nom::bytes::complete::tag("-")(i)
    }

    fn infix_operator_multiply(i: &str) -> ParseResult {
        nom::bytes::complete::tag("*")(i)
    }

    fn infix_operator_divide(i: &str) -> ParseResult {
        nom::bytes::complete::tag("/")(i)
    }

    fn infix_operator_modulo(i: &str) -> ParseResult {
        nom::bytes::complete::tag("%")(i)
    }

    fn infix_operator(i: &str) -> ParseResult {
        nom::branch::alt((
            infix_operator_or,
            infix_operator_and,
            infix_operator_single_or,
            infix_operator_xor,
            infix_operator_single_and,
            infix_operator_equals,
            infix_operator_not_equals,
            infix_operator_less_than,
            infix_operator_greater_than,
            infix_operator_less_than_or_equal,
            infix_operator_greater_than_or_equal,
            infix_operator_left_shift,
            infix_operator_right_shift_signed,
            infix_operator_right_shift_unsigned,
            infix_operator_add,
            infix_operator_subtract,
            infix_operator_multiply,
            infix_operator_divide,
            infix_operator_modulo,
        ))(i)
    }

    fn plus_one_operator(i: &str) -> ParseResult {
        nom::bytes::complete::tag("++")(i)
    }

    fn minus_one_operator(i: &str) -> ParseResult {
        nom::bytes::complete::tag("--")(i)
    }

    fn prefix_operator_not(i: &str) -> ParseResult {
        nom::bytes::complete::tag("!")(i)
    }

    fn prefix_operator_compliment(i: &str) -> ParseResult {
        nom::bytes::complete::tag("~")(i)
    }

    fn prefix_operator_plus(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("+")(i)
    }

    fn prefix_operator_minus(i: &str) -> nom::IResult<&str, &str> {
        nom::bytes::complete::tag("-")(i)
    }

    fn prefix_operator(i: &str) -> nom::IResult<&str, &str> {
        nom::branch::alt((
            plus_one_operator,
            minus_one_operator,
            prefix_operator_not,
            prefix_operator_compliment,
            prefix_operator_plus,
            prefix_operator_minus,
        ))(i)
    }

    fn postfix_operator(i: &str) -> nom::IResult<&str, &str> {
        nom::branch::alt((
            plus_one_operator,
            minus_one_operator,
        ))(i)
    }

    fn true_literal(i: &str) -> ParseResult {
        nom::bytes::complete::tag("true")(i)
    }

    fn false_literal(i: &str) -> ParseResult {
        nom::bytes::complete::tag("false")(i)
    }

    fn boolean_literal(i: &str) -> ParseResult {
        nom::branch::alt((
            true_literal,
            false_literal,
        ))(i)
    }

    fn visibility_public(i: &str) -> ParseResult {
        nom::bytes::complete::tag("public")(i)
    }

    fn visibility_protected(i: &str) -> ParseResult {
        nom::bytes::complete::tag("protected")(i)
    }

    fn visibility_private(i: &str) -> ParseResult {
        nom::bytes::complete::tag("private")(i)
    }

    fn visibility(i: &str) -> ParseResult {
        alt((
            visibility_public,
            visibility_protected,
            visibility_private,
        ))(i)
    }

    fn letter(i: char) -> bool {
        i.is_alphabetic() || i == '_' || i == '$'
    }

    fn letter_or_digit(i: char) -> bool {
        letter(i) || i.is_numeric()
    }

    fn identifier(i: &str) -> ParseResult {
        //TODO: Deal with keyword failures
        recognize(tuple((
            take_while1(letter),
            take_while(letter_or_digit)
        )))(i)
    }

    fn abstract_keyword(i: &str) -> ParseResult {
        tag("abstract")(i)
    }

    fn assert_keyword(i: &str) -> ParseResult {
        tag("assert")(i)
    }

    fn break_keyword(i: &str) -> ParseResult {
        tag("break")(i)
    }

    fn case_keyword(i: &str) -> ParseResult {
        tag("case")(i)
    }

    fn catch_keyword(i: &str) -> ParseResult {
        tag("catch")(i)
    }

    fn class_keyword(i: &str) -> ParseResult {
        tag("class")(i)
    }

    fn const_keyword(i: &str) -> ParseResult {
        tag("const")(i)
    }

    fn continue_keyword(i: &str) -> ParseResult {
        tag("continue")(i)
    }

    fn default_keyword(i: &str) -> ParseResult {
        tag("default")(i)
    }

    fn do_keyword(i: &str) -> ParseResult {
        tag("do")(i)
    }

    fn else_keyword(i: &str) -> ParseResult {
        tag("else")(i)
    }

    fn enum_keyword(i: &str) -> ParseResult {
        tag("enum")(i)
    }

    fn extends_keyword(i: &str) -> ParseResult {
        tag("extends")(i)
    }

    fn final_keyword(i: &str) -> ParseResult {
        tag("final")(i)
    }

    fn finally_keyword(i: &str) -> ParseResult {
        tag("finally")(i)
    }

    fn for_keyword(i: &str) -> ParseResult {
        tag("for")(i)
    }

    fn if_keyword(i: &str) -> ParseResult {
        tag("if")(i)
    }

    fn goto_keyword(i: &str) -> ParseResult {
        tag("goto")(i)
    }

    fn implements_keyword(i: &str) -> ParseResult {
        tag("implements")(i)
    }

    fn import_keyword(i: &str) -> ParseResult {
        tag("import")(i)
    }

    fn instanceof_keyword(i: &str) -> ParseResult {
        tag("instanceof")(i)
    }

    fn interface_keyword(i: &str) -> ParseResult {
        tag("interface")(i)
    }

    fn native_keyword(i: &str) -> ParseResult {
        tag("native")(i)
    }

    fn new_keyword(i: &str) -> ParseResult {
        tag("new")(i)
    }

    fn package_keyword(i: &str) -> ParseResult {
        tag("package")(i)
    }

    fn return_keyword(i: &str) -> ParseResult {
        tag("return")(i)
    }

    fn static_keyword(i: &str) -> ParseResult {
        tag("static")(i)
    }

    fn strictfp_keyword(i: &str) -> ParseResult {
        tag("strictfp")(i)
    }

    fn super_keyword(i: &str) -> ParseResult {
        tag("super")(i)
    }

    fn switch_keyword(i: &str) -> ParseResult {
        tag("switch")(i)
    }

    fn synchronized_keyword(i: &str) -> ParseResult {
        tag("synchronized")(i)
    }

    fn this_keyword(i: &str) -> ParseResult {
        tag("this")(i)
    }

    fn throw_keyword(i: &str) -> ParseResult {
        tag("throw")(i)
    }

    fn throws_keyword(i: &str) -> ParseResult {
        tag("throws")(i)
    }

    fn transient_keyword(i: &str) -> ParseResult {
        tag("transient")(i)
    }

    fn try_keyword(i: &str) -> ParseResult {
        tag("try")(i)
    }

    fn void_keyword(i: &str) -> ParseResult {
        tag("void")(i)
    }

    fn volatile_keyword(i: &str) -> ParseResult {
        tag("volatile")(i)
    }

    fn while_keyword(i: &str) -> ParseResult {
        tag("while")(i)
    }

    fn modifier(i: &str) -> ParseResult {
        // TODO: Needs annotation processing
        alt((
            visibility,
            static_keyword,
            abstract_keyword,
            final_keyword,
            native_keyword,
            synchronized_keyword,
            transient_keyword,
            volatile_keyword,
            strictfp_keyword,
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

        #[test]
        fn test_infix_operator_or() {
            assert_eq!(infix_operator_or("||"), Ok(("", "||")));
            assert_eq!(infix_operator_or("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_infix_operator_and() {
            assert_eq!(infix_operator_and("&&"), Ok(("", "&&")));
            assert_eq!(infix_operator_and("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_infix_operator_single_or() {
            assert_eq!(infix_operator_single_or("|"), Ok(("", "|")));
            assert_eq!(infix_operator_single_or("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_infix_operator_xor() {
            assert_eq!(infix_operator_xor("^"), Ok(("", "^")));
            assert_eq!(infix_operator_xor("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_infix_operator_single_and() {
            assert_eq!(infix_operator_single_and("&"), Ok(("", "&")));
            assert_eq!(infix_operator_single_and("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_infix_operator_equals() {
            assert_eq!(infix_operator_equals("=="), Ok(("", "==")));
            assert_eq!(infix_operator_equals("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_infix_operator_not_equals() {
            assert_eq!(infix_operator_not_equals("!="), Ok(("", "!=")));
            assert_eq!(infix_operator_not_equals("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_infix_operator_less_than() {
            assert_eq!(infix_operator_less_than("<"), Ok(("", "<")));
            assert_eq!(infix_operator_less_than("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_infix_operator_greater_than() {
            assert_eq!(infix_operator_greater_than(">"), Ok(("", ">")));
            assert_eq!(infix_operator_greater_than("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_infix_operator_less_than_or_equal() {
            assert_eq!(infix_operator_less_than_or_equal("<="), Ok(("", "<=")));
            assert_eq!(infix_operator_less_than_or_equal("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_infix_operator_greater_than_or_equals() {
            assert_eq!(infix_operator_greater_than_or_equal(">="), Ok(("", ">=")));
            assert_eq!(infix_operator_greater_than_or_equal("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_infix_operator_left_shift() {
            assert_eq!(infix_operator_left_shift("<<"), Ok(("", "<<")));
            assert_eq!(infix_operator_left_shift("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_infix_operator_right_shift_signed() {
            assert_eq!(infix_operator_right_shift_signed(">>"), Ok(("", ">>")));
            assert_eq!(infix_operator_right_shift_signed("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_infix_operator_right_shift_unsigned() {
            assert_eq!(infix_operator_right_shift_unsigned(">>>"), Ok(("", ">>>")));
            assert_eq!(infix_operator_right_shift_unsigned("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_infix_operator_add() {
            assert_eq!(infix_operator_add("+"), Ok(("", "+")));
            assert_eq!(infix_operator_add("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_infix_operator_subtract() {
            assert_eq!(infix_operator_subtract("-"), Ok(("", "-")));
            assert_eq!(infix_operator_subtract("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_infix_operator_multiply() {
            assert_eq!(infix_operator_multiply("*"), Ok(("", "*")));
            assert_eq!(infix_operator_multiply("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_infix_operator_divide() {
            assert_eq!(infix_operator_divide("/"), Ok(("", "/")));
            assert_eq!(infix_operator_divide("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_infix_operator_modulo() {
            assert_eq!(infix_operator_modulo("%"), Ok(("", "%")));
            assert_eq!(infix_operator_modulo("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_prefix_operator_plus_one() {
            assert_eq!(plus_one_operator("++"), Ok(("", "++")));
            assert_eq!(plus_one_operator("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_prefix_operator_minus_one() {
            assert_eq!(minus_one_operator("--"), Ok(("", "--")));
            assert_eq!(minus_one_operator("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_prefix_operator_minus() {
            assert_eq!(prefix_operator_minus("-"), Ok(("", "-")));
            assert_eq!(prefix_operator_minus("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_prefix_operator_not() {
            assert_eq!(prefix_operator_not("!"), Ok(("", "!")));
            assert_eq!(prefix_operator_not("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_prefix_operator_plus() {
            assert_eq!(prefix_operator_plus("+"), Ok(("", "+")));
            assert_eq!(prefix_operator_plus("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_prefix_operator_compliment() {
            assert_eq!(prefix_operator_compliment("~"), Ok(("", "~")));
            assert_eq!(prefix_operator_compliment("="), Err(nom::Err::Error(("=", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_postfix_operator() {
            assert_eq!(postfix_operator("++"), Ok(("", "++")));
            assert_eq!(postfix_operator("--"), Ok(("", "--")));
            assert_eq!(postfix_operator("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_true_literal() {
            assert_eq!(true_literal("true"), Ok(("", "true")));
            assert_eq!(true_literal("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
            assert_eq!(true_literal("false"), Err(nom::Err::Error(("false", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_false_literal() {
            assert_eq!(false_literal("false"), Ok(("", "false")));
            assert_eq!(false_literal("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
            assert_eq!(false_literal("true"), Err(nom::Err::Error(("true", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_boolean_literal() {
            assert_eq!(boolean_literal("false"), Ok(("", "false")));
            assert_eq!(boolean_literal("true"), Ok(("", "true")));
            assert_eq!(boolean_literal("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_visiblity_public() {
            assert_eq!(visibility_public("public"), Ok(("", "public")));
            assert_eq!(visibility_public("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_visiblity_protected() {
            assert_eq!(visibility_protected("protected"), Ok(("", "protected")));
            assert_eq!(visibility_protected("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_visiblity_private() {
            assert_eq!(visibility_private("private"), Ok(("", "private")));
            assert_eq!(visibility_private("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_identifier() {
            assert_eq!(identifier("_stuff1"), Ok(("", "_stuff1")));
            assert_eq!(identifier("i"), Ok(("", "i")));
            assert_eq!(identifier("W2"), Ok(("", "W2")));
            assert_eq!(identifier("1stuff"), Err(nom::Err::Error(("1stuff", nom::error::ErrorKind::TakeWhile1))));
        }

        #[test]
        fn test_abstract_keyword() {
            assert_eq!(abstract_keyword("abstract"), Ok(("", "abstract")));
            assert_eq!(abstract_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_assert_keyword() {
            assert_eq!(assert_keyword("assert"), Ok(("", "assert")));
            assert_eq!(assert_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_break_keyword() {
            assert_eq!(break_keyword("break"), Ok(("", "break")));
            assert_eq!(break_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_case_keyword() {
            assert_eq!(case_keyword("case"), Ok(("", "case")));
            assert_eq!(case_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_catch_keyword() {
            assert_eq!(catch_keyword("catch"), Ok(("", "catch")));
            assert_eq!(catch_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_class_keyword() {
            assert_eq!(class_keyword("class"), Ok(("", "class")));
            assert_eq!(class_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_const_keyword() {
            assert_eq!(const_keyword("const"), Ok(("", "const")));
            assert_eq!(const_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_continue_keyword() {
            assert_eq!(continue_keyword("continue"), Ok(("", "continue")));
            assert_eq!(continue_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_default_keyword() {
            assert_eq!(default_keyword("default"), Ok(("", "default")));
            assert_eq!(default_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_do_keyword() {
            assert_eq!(do_keyword("do"), Ok(("", "do")));
            assert_eq!(do_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_else_keyword() {
            assert_eq!(else_keyword("else"), Ok(("", "else")));
            assert_eq!(else_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_enum_keyword() {
            assert_eq!(enum_keyword("enum"), Ok(("", "enum")));
            assert_eq!(enum_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_extends_keyword() {
            assert_eq!(extends_keyword("extends"), Ok(("", "extends")));
            assert_eq!(extends_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_final_keyword() {
            assert_eq!(final_keyword("final"), Ok(("", "final")));
            assert_eq!(final_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_finally_keyword() {
            assert_eq!(finally_keyword("finally"), Ok(("", "finally")));
            assert_eq!(finally_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_for_keyword() {
            assert_eq!(for_keyword("for"), Ok(("", "for")));
            assert_eq!(for_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_if_keyword() {
            assert_eq!(if_keyword("if"), Ok(("", "if")));
            assert_eq!(if_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_goto_keyword() {
            assert_eq!(goto_keyword("goto"), Ok(("", "goto")));
            assert_eq!(goto_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_implements_keyword() {
            assert_eq!(implements_keyword("implements"), Ok(("", "implements")));
            assert_eq!(implements_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_import_keyword() {
            assert_eq!(import_keyword("import"), Ok(("", "import")));
            assert_eq!(import_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_instanceof_keyword() {
            assert_eq!(instanceof_keyword("instanceof"), Ok(("", "instanceof")));
            assert_eq!(instanceof_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_interface_keyword() {
            assert_eq!(interface_keyword("interface"), Ok(("", "interface")));
            assert_eq!(interface_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_native_keyword() {
            assert_eq!(native_keyword("native"), Ok(("", "native")));
            assert_eq!(native_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_new_keyword() {
            assert_eq!(new_keyword("new"), Ok(("", "new")));
            assert_eq!(new_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_package_keyword() {
            assert_eq!(package_keyword("package"), Ok(("", "package")));
            assert_eq!(package_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_return_keyword() {
            assert_eq!(return_keyword("return"), Ok(("", "return")));
            assert_eq!(return_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_static_keyword() {
            assert_eq!(static_keyword("static"), Ok(("", "static")));
            assert_eq!(static_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_strictfp_keyword() {
            assert_eq!(strictfp_keyword("strictfp"), Ok(("", "strictfp")));
            assert_eq!(strictfp_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_super_keyword() {
            assert_eq!(super_keyword("super"), Ok(("", "super")));
            assert_eq!(super_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_switch_keyword() {
            assert_eq!(switch_keyword("switch"), Ok(("", "switch")));
            assert_eq!(switch_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_synchronized_keyword() {
            assert_eq!(synchronized_keyword("synchronized"), Ok(("", "synchronized")));
            assert_eq!(synchronized_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_this_keyword() {
            assert_eq!(this_keyword("this"), Ok(("", "this")));
            assert_eq!(this_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_throw_keyword() {
            assert_eq!(throw_keyword("throw"), Ok(("", "throw")));
            assert_eq!(throw_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_throws_keyword() {
            assert_eq!(throws_keyword("throws"), Ok(("", "throws")));
            assert_eq!(throws_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_transient_keyword() {
            assert_eq!(transient_keyword("transient"), Ok(("", "transient")));
            assert_eq!(transient_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_try_keyword() {
            assert_eq!(try_keyword("try"), Ok(("", "try")));
            assert_eq!(try_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_void_keyword() {
            assert_eq!(void_keyword("void"), Ok(("", "void")));
            assert_eq!(void_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_volatile_keyword() {
            assert_eq!(volatile_keyword("volatile"), Ok(("", "volatile")));
            assert_eq!(volatile_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_while_keyword() {
            assert_eq!(while_keyword("while"), Ok(("", "while")));
            assert_eq!(while_keyword("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }

        #[test]
        fn test_modifier() {
            assert_eq!(modifier("public"), Ok(("", "public")));
            assert_eq!(modifier("final"), Ok(("", "final")));
            assert_eq!(modifier("strictfp"), Ok(("", "strictfp")));
            assert_eq!(modifier("!"), Err(nom::Err::Error(("!", nom::error::ErrorKind::Tag))));
        }
    }
}