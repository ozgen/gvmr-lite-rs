use super::*;

#[test]
fn severity_color_returns_expected_rgb_values() {
    assert_eq!(severity_color("critical"), (139, 0, 0));
    assert_eq!(severity_color("High"), (220, 20, 60));
    assert_eq!(severity_color(" medium "), (255, 140, 0));
    assert_eq!(severity_color("low"), (80, 160, 200));
    assert_eq!(severity_color("log"), (30, 144, 255));
    assert_eq!(severity_color("false positive"), (128, 128, 128));
    assert_eq!(severity_color("unknown"), (100, 100, 100));
}

#[test]
fn clean_text_removes_null_and_control_chars_and_normalizes_unicode_punctuation() {
    let text = "hello\u{0000}\u{0007} “world” ‘test’ – dash — more …\n\t";

    let cleaned = clean_text(text);

    assert_eq!(cleaned, "hello \"world\" 'test' - dash - more ...\n\t");
}

#[test]
fn truncate_text_returns_original_when_within_limit() {
    assert_eq!(truncate_text("hello", 5), "hello");
}

#[test]
fn truncate_text_truncates_by_chars_not_bytes() {
    assert_eq!(truncate_text("äöühello", 3), "äöü\n\n[truncated]");
}

#[test]
fn estimate_line_count_returns_zero_for_blank_text() {
    assert_eq!(estimate_line_count("", 80), 0);
    assert_eq!(estimate_line_count("   \n\t", 80), 0);
}

#[test]
fn estimate_line_count_counts_non_empty_lines() {
    assert_eq!(estimate_line_count("abc", 10), 1);
    assert_eq!(estimate_line_count("abc\ndef", 10), 2);
}

#[test]
fn estimate_line_count_counts_wrapped_lines() {
    assert_eq!(estimate_line_count("abcdefghijk", 5), 3);
}

#[test]
fn wrap_text_wraps_words_without_exceeding_limit_when_possible() {
    let lines = wrap_text("one two three four", 8);

    assert_eq!(lines, vec!["one two", "three", "four"]);
}

#[test]
fn wrap_text_preserves_empty_paragraphs() {
    let lines = wrap_text("one\n\nthree", 10);

    assert_eq!(lines, vec!["one", "", "three"]);
}

#[test]
fn wrap_text_keeps_long_word_on_own_line() {
    let lines = wrap_text("short veryverylongword end", 5);

    assert_eq!(lines, vec!["short", "veryverylongword", "end"]);
}
