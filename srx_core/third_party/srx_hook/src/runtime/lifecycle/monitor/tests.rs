use super::parse_periodic_env_value;

#[test]
fn parse_periodic_env_true_values() {
    assert_eq!(parse_periodic_env_value("1"), Some(true));
    assert_eq!(parse_periodic_env_value("true"), Some(true));
    assert_eq!(parse_periodic_env_value("YES"), Some(true));
    assert_eq!(parse_periodic_env_value(" on "), Some(true));
}

#[test]
fn parse_periodic_env_false_values() {
    assert_eq!(parse_periodic_env_value("0"), Some(false));
    assert_eq!(parse_periodic_env_value("false"), Some(false));
    assert_eq!(parse_periodic_env_value("No"), Some(false));
    assert_eq!(parse_periodic_env_value(" off "), Some(false));
}

#[test]
fn parse_periodic_env_invalid_value() {
    assert_eq!(parse_periodic_env_value("maybe"), None);
    assert_eq!(parse_periodic_env_value(""), None);
}
