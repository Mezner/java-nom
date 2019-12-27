use std::path::PathBuf;
use std::io::BufRead;

#[derive(Default)]
pub struct ParseError;

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "A parsing error occurred.")
    }
}

impl std::fmt::Debug for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <ParseError as std::fmt::Display>::fmt(self, f)
    }
}

impl std::error::Error for ParseError { }

#[derive(Clone, Default, Debug)]
pub struct Mount {
    pub device: String,
    pub mount_point: String,
    pub file_system_type: String,
    pub options: Vec<String>,
}

pub fn mounts(path: &PathBuf) -> Result<Vec<Mount>, std::boxed::Box<dyn std::error::Error>> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut mounts = Vec::new();
    for line in reader.lines() {
        match parsers::parse_line(&line?) {
            Ok((_, m)) => {
                mounts.push(m);
            }
            Err(_) => return Err(ParseError::default().into())
        }
    }
    Ok(mounts)
}

pub(self) mod parsers {
    use super::Mount;

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

    fn basic_type(i: &str) -> nom::IResult<&str, &str> {
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

    pub fn parse_line(i: &str) -> nom::IResult<&str, Mount> {
        match nom::combinator::all_consuming(nom::sequence::tuple((
            nom::combinator::map_parser(not_whitespace, transform_escaped),
            nom::character::complete::space1,
            nom::combinator::map_parser(not_whitespace, transform_escaped),
            nom::character::complete::space1,
            not_whitespace, // file_system_type
            nom::character::complete::space1,
            mount_opts, // options
            nom::character::complete::space1,
            nom::character::complete::char('0'),
            nom::character::complete::space1,
            nom::character::complete::char('0'),
            nom::character::complete::space0,
        )))(i) {
            Ok((remaining_input, (
                device,
                _,
                mount_point,
                _,
                file_system_type,
                _,
                options,
                _,
                _,
                _,
                _,
                _,
            ))) => {
                Ok((remaining_input, Mount {
                    device,
                    mount_point,
                    file_system_type: file_system_type.to_string(),
                    options
                }))
            },
            Err(e) => Err(e)
        }
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
        fn test_parse_line() {
            let mount = Mount{
                device: "device".to_string(),
                mount_point: "mount_point".to_string(),
                file_system_type: "file_system_type".to_string(),
                options: vec!["options".to_string(), "a".to_string(), "b=c".to_string(), "d e".to_string()]
            };
            let (_, expected) = parse_line("device mount_point file_system_type options,a,b=c,d\\040e 0 0").unwrap();
            assert_eq!(mount.device, expected.device);
            assert_eq!(mount.mount_point, expected.mount_point);
            assert_eq!(mount.file_system_type, expected.file_system_type);
            assert_eq!(mount.options, expected.options);
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
    }
}