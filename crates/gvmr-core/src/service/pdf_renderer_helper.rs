pub fn severity_color(threat: &str) -> (u8, u8, u8) {
    match threat.trim().to_ascii_lowercase().as_str() {
        "critical" => (139, 0, 0),
        "high" => (220, 20, 60),
        "medium" => (255, 140, 0),
        "low" => (80, 160, 200),
        "log" => (30, 144, 255),
        "false positive" => (128, 128, 128),
        _ => (100, 100, 100),
    }
}

pub fn clean_text(value: &str) -> String {
    value
        .replace('\u{0000}', "")
        .replace(['“', '”'], "\"")
        .replace(['‘', '’'], "'")
        .replace(['–', '—'], "-")
        .replace('…', "...")
        .chars()
        .filter(|ch| *ch == '\n' || *ch == '\t' || !ch.is_control())
        .collect()
}

pub fn truncate_text(value: &str, max_chars: usize) -> String {
    let count = value.chars().count();

    if count <= max_chars {
        return value.to_string();
    }

    let mut out = value.chars().take(max_chars).collect::<String>();
    out.push_str("\n\n[truncated]");
    out
}

pub fn estimate_line_count(text: &str, chars_per_line: usize) -> usize {
    if text.trim().is_empty() {
        return 0;
    }

    text.lines()
        .map(|line| {
            let len = line.chars().count();

            if len == 0 {
                1
            } else {
                len.div_ceil(chars_per_line)
            }
        })
        .sum()
}

pub fn wrap_text(text: &str, chars_per_line: usize) -> Vec<String> {
    let mut lines = Vec::new();

    for paragraph in text.split('\n') {
        let paragraph = paragraph.trim();

        if paragraph.is_empty() {
            lines.push(String::new());
            continue;
        }

        let mut line = String::new();

        for word in paragraph.split_whitespace() {
            let extra_space = usize::from(!line.is_empty());

            if line.chars().count() + word.chars().count() + extra_space > chars_per_line
                && !line.is_empty()
            {
                lines.push(line);
                line = String::new();
            }

            if !line.is_empty() {
                line.push(' ');
            }

            line.push_str(word);
        }

        if !line.is_empty() {
            lines.push(line);
        }
    }

    lines
}

#[cfg(test)]
#[path = "pdf_renderer_helper_tests.rs"]
mod pdf_renderer_helper_tests;
