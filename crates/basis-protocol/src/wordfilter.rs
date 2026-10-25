//! Port of BasisNetworkServer.BasisNetworkServer.BasisWordFilter.
//!
//! The C# implementation walks grapheme clusters and uses a homoglyph table plus a
//! 3-gram false-positive guard. Chat text is overwhelmingly single-scalar elements, so
//! this port operates on `char`s; the homoglyph table and trigram list are generated
//! from the C# source in `wordfilter_data.rs`.

use crate::wordfilter_data::{HOMOGLYPHS, TRIGRAMS};
use crate::wordfilter_words::DEFAULT_WORDS;
use std::collections::HashSet;
use std::sync::OnceLock;

static DEFAULT_WORDS_OWNED: OnceLock<Vec<String>> = OnceLock::new();
static TRIGRAM_SET: OnceLock<HashSet<&'static str>> = OnceLock::new();

fn trigram_set() -> &'static HashSet<&'static str> {
    TRIGRAM_SET.get_or_init(|| TRIGRAMS.iter().copied().collect())
}

fn default_words() -> &'static [String] {
    DEFAULT_WORDS_OWNED.get_or_init(|| DEFAULT_WORDS.iter().map(|word| word.to_string()).collect())
}

/// Filters with the C# server's default `chat_word_filter.txt` contents.
pub fn filter_default(text: &str) -> String {
    filter(text, default_words())
}

/// Owned copy of the default word list for callers that load a custom file.
pub fn default_words_vec() -> Vec<String> {
    default_words().to_vec()
}

/// Contents of the C#-compatible default `chat_word_filter.txt`.
pub fn default_file_contents() -> String {
    let mut out = String::from(
        "# Chat word filter - one word or phrase per line\n\
         # Lines starting with # are comments\n\
         # Words are case-insensitive\n",
    );
    for word in DEFAULT_WORDS {
        out.push_str(word);
        out.push('\n');
    }
    out
}

fn lower(c: char) -> char {
    c.to_lowercase().next().unwrap_or(c)
}

fn is_homoglyph(expected: char, element: char) -> bool {
    if lower(expected) == lower(element) {
        return true;
    }
    let expected = lower(expected);
    HOMOGLYPHS
        .iter()
        .find(|(key, _)| *key == expected)
        .map(|(_, values)| values.contains(element))
        .unwrap_or(false)
}

fn is_valid_trigram(trigram: &str, banned_word: &str) -> bool {
    if trigram.chars().count() != 3 {
        return false;
    }
    if banned_word.to_lowercase().contains(trigram) {
        return false;
    }
    trigram_set().contains(trigram)
}

fn check_trigram(elements: &[char], index: usize, banned_word: &str) -> bool {
    let current = lower(elements[index]);
    if index + 2 < elements.len() {
        let tri: String = [
            current,
            lower(elements[index + 1]),
            lower(elements[index + 2]),
        ]
        .iter()
        .collect();
        if is_valid_trigram(&tri, banned_word) {
            return true;
        }
    }
    if index >= 2 {
        let tri: String = [
            lower(elements[index - 2]),
            lower(elements[index - 1]),
            current,
        ]
        .iter()
        .collect();
        if is_valid_trigram(&tri, banned_word) {
            return true;
        }
    }
    if index >= 1 && index + 1 < elements.len() {
        let tri: String = [
            lower(elements[index - 1]),
            current,
            lower(elements[index + 1]),
        ]
        .iter()
        .collect();
        if is_valid_trigram(&tri, banned_word) {
            return true;
        }
    }
    false
}

fn is_embedded_in_word(elements: &[char], matched: &[usize]) -> bool {
    if matched.len() < 2 {
        return false;
    }
    let first = matched[0];
    let last = *matched.last().unwrap();

    if last + 1 < elements.len() {
        let next = elements[last + 1];
        if next.is_alphabetic() {
            let second_last = elements[matched[matched.len() - 2]];
            let tri: String = [lower(second_last), lower(elements[last]), lower(next)]
                .iter()
                .collect();
            if trigram_set().contains(tri.as_str()) {
                return true;
            }
        }
    }
    if first > 0 {
        let previous = elements[first - 1];
        if previous.is_alphabetic() {
            let first_value = elements[matched[0]];
            let second = elements[matched[1]];
            let tri: String = [lower(previous), lower(first_value), lower(second)]
                .iter()
                .collect();
            if trigram_set().contains(tri.as_str()) {
                return true;
            }
        }
    }
    false
}

/// True when `text` contains a banned word. This mirrors the C# scan and only
/// returns an explicit match for callers that need the matched word.
pub fn contains_banned_word(text: &str, words: &[String]) -> Option<String> {
    if text.is_empty() || words.is_empty() {
        return None;
    }
    let elements: Vec<char> = text.chars().collect();
    for word in words {
        if word.is_empty() {
            continue;
        }
        let target: Vec<char> = word.chars().collect();
        let mut state = 0usize;
        let mut matched = Vec::new();
        for (index, element) in elements.iter().enumerate() {
            if state >= target.len() {
                break;
            }
            let expected = target[state];
            let is_homoglyph = is_homoglyph(expected, *element);
            let is_trigram = check_trigram(&elements, index, word);
            if is_homoglyph && !is_trigram {
                matched.push(index);
                state += 1;
            } else if is_trigram && state > 0 {
                matched.pop();
                state -= 1;
            }
            if state == target.len() {
                if !is_embedded_in_word(&elements, &matched) {
                    return Some(word.clone());
                }
                state = 0;
                matched.clear();
            }
        }
    }
    None
}

/// Replaces banned-word characters with `*`, matching BasisWordFilter.Filter.
pub fn filter(text: &str, words: &[String]) -> String {
    if text.is_empty() || words.is_empty() {
        return text.to_string();
    }
    let mut result: Vec<char> = text.chars().collect();
    for word in words {
        if word.is_empty() {
            continue;
        }
        let target: Vec<char> = word.chars().collect();
        loop {
            let elements = result.clone();
            let mut state = 0usize;
            let mut matched = Vec::new();
            let mut found = false;
            for (index, element) in elements.iter().enumerate() {
                if state >= target.len() {
                    break;
                }
                let expected = target[state];
                let is_homoglyph = is_homoglyph(expected, *element);
                let is_trigram = check_trigram(&elements, index, word);
                if is_homoglyph && !is_trigram {
                    matched.push(index);
                    state += 1;
                } else if is_trigram && state > 0 {
                    matched.pop();
                    state -= 1;
                }
                if state == target.len() {
                    if is_embedded_in_word(&elements, &matched) {
                        state = 0;
                        matched.clear();
                        continue;
                    }
                    for position in &matched {
                        result[*position] = '*';
                    }
                    found = true;
                    break;
                }
            }
            if !found {
                break;
            }
        }
    }
    result.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn exact_words_are_masked() {
        assert_eq!(filter("damn", &words(&["damn"])), "****");
        assert_eq!(filter("ass", &words(&["ass"])), "***");
        assert_eq!(filter("you damn fool", &words(&["damn"])), "you **** fool");
        assert_eq!(filter("DAMN", &words(&["damn"])), "****");
    }

    #[test]
    fn embedded_words_are_not_masked() {
        assert_eq!(filter("assignment", &words(&["ass"])), "assignment");
        assert_eq!(filter("classic", &words(&["ass"])), "classic");
    }

    #[test]
    fn homoglyphs_are_detected() {
        assert_eq!(filter("d@mn", &words(&["damn"])), "****");
    }

    #[test]
    fn contains_reports_first_list_entry_that_matches() {
        assert_eq!(
            contains_banned_word("you damn fool", &words(&["damn"])),
            Some("damn".to_string())
        );
        assert_eq!(
            contains_banned_word("crap damn", &words(&["damn", "crap"])),
            Some("damn".to_string())
        );
        assert_eq!(contains_banned_word("assignment", &words(&["ass"])), None);
    }

    #[test]
    fn filter_is_idempotent() {
        let list = words(&["damn", "crap", "ass"]);
        for input in [
            "you damn fool",
            "d a m n",
            "damn crap",
            "assignment",
            "DAMN",
        ] {
            let once = filter(input, &list);
            assert_eq!(filter(&once, &list), once, "{input}");
        }
    }

    #[test]
    fn default_filter_masks_a_default_word() {
        assert_eq!(filter_default("damn"), "****");
        assert_eq!(filter_default("hello"), "hello");
    }

    #[test]
    fn punctuation_and_boundaries_match_csharp() {
        assert_eq!(filter("damn!", &words(&["damn"])), "****!");
        assert_eq!(filter("(damn)", &words(&["damn"])), "(****)");
        assert_eq!(filter("my ass.", &words(&["ass"])), "my ***.");
        assert_eq!(filter("my ass hurts", &words(&["ass"])), "my *** hurts");
        assert_eq!(filter("that was damn", &words(&["damn"])), "that was ****");
    }

    #[test]
    fn clean_and_embedded_sentences_match_csharp() {
        for text in [
            "hello there friend",
            "The quick brown fox jumps over the lazy dog.",
            "a simple sentence",
        ] {
            assert_eq!(filter(text, &words(&["ass"])), text);
        }
        for (text, word) in [
            ("assignment", "ass"),
            ("class", "ass"),
            ("bass", "ass"),
            ("assassinate", "ass"),
            ("scrape", "crap"),
            ("crappy", "crap"),
            ("damnation", "damn"),
            ("car-479129", "crap"),
        ] {
            assert_eq!(filter(text, &words(&[word])), text, "{text}");
        }
    }

    #[test]
    fn insertions_and_homoglyphs_match_csharp() {
        assert_eq!(filter("d a m n", &words(&["damn"])), "* * * *");
        assert_eq!(filter("d.a.m.n", &words(&["damn"])), "*.*.*.*");
        assert_eq!(filter("da\u{200B}mn", &words(&["damn"])), "**\u{200B}**");
        assert_eq!(filter("d@mn", &words(&["damn"])), "****");
        assert_eq!(filter("d4mn", &words(&["damn"])), "****");
        assert_eq!(filter("d\u{03B1}mn", &words(&["damn"])), "****");
        assert_eq!(
            filter("\u{FF44}\u{FF41}\u{FF4D}\u{FF4E}", &words(&["damn"])),
            "****"
        );
        assert_eq!(filter("d\u{00E2}mn", &words(&["damn"])), "d\u{00E2}mn");
    }

    #[test]
    fn phrases_and_repetition_match_csharp() {
        assert_eq!(
            filter("please go die now", &words(&["go die"])),
            "please ****** now"
        );
        assert_eq!(
            filter("go outside and die", &words(&["go die"])),
            "go outside and die"
        );
        assert_eq!(filter("damn crap", &words(&["damn", "crap"])), "**** ****");
        assert_eq!(
            filter("damn damn damn", &words(&["damn"])),
            "**** **** ****"
        );
    }
}
