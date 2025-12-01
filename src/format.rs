pub fn format_as_prefix_list(prefixes: &[String], min_length: Option<u8>) -> String {
    let mut lines = vec![];
    let mut line_index = 10;

    for prefix in prefixes {
        if let Some((_, cidr)) = parse_cidr(prefix) {
            let le_str = match min_length {
                Some(min) if cidr < min => {
                    format!(" le {}", min)
                }
                _ => String::new(),
            };

            lines.push(format!("seq {} permit {}{}", line_index, prefix, le_str));
            line_index = line_index + 10;
        }
    }
    lines.join("\n")
}

fn parse_cidr(prefix: &str) -> Option<(String, u8)> {
    let parts: Vec<&str> = prefix.split('/').collect();
    if parts.len() == 2 {
        parts[1]
            .parse::<u8>()
            .ok()
            .map(|cidr| (parts[0].to_string(), cidr))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_list_conversion() {
        let prefixes = vec![
            "192.168.0.0/16".to_string(),
            "172.16.10.0/24".to_string(),
            "10.0.0.0/8".to_string(),
        ];
        let min = Some(24);

        let result = format_as_prefix_list(&prefixes, min);

        assert_eq!(
            result,
            "seq 10 permit 192.168.0.0/16 le 24
seq 20 permit 172.16.10.0/24
seq 30 permit 10.0.0.0/8 le 24"
        )
    }
}
