// This document outlines different ways of fuzzing a library:
//  - Invariant Fuzzing
//  - Differential Fuzzing
//  - Correctness Fuzzing
//  - Consistency Fuzzing
//  - Idempotency Fuzzing

// Invariant Fuzzing
// We run the program, and check the correctness of important values.
// For example, we could check that a process is always successful by calling `.unwrap()`, or we
// could assert that a certain value satisfies a property.
fn invariant_fuzz(data: &str) {
    if let Ok(parsed) = url::Url::parse(data) {
        #[cfg(not(fuzzing))]
        println!("{data} => {parsed}");
        // We assert that the string representation of the URL always contains a ':'
        // character.
        assert!(parsed.to_string().contains(':'));
    }
}

// Differential Fuzzing
// We run two implementations of the same process on identical data and verify that the outputs
// match.
fn differential_fuzz(data: &str) {
    // We do not have an alternative implementation, so we mock one.
    let other_parse = url::Url::parse;
    // We run both `parse` methods and assert the results are equal.
    if let (Ok(parsed), Ok(parsed_other)) = (url::Url::parse(data), other_parse(data)) {
        assert_eq!(parsed, parsed_other);
    }
}

// Correctness Fuzzing
// TODO Definition
fn correctness_fuzz(_data: &str) {
    // TODO Implementation
}

// Consistency Fuzzing
// TODO Definition
fn consistency_fuzz(_data: &str) {
    // TODO Implementation
}

// Idempotency Fuzzing
// We run sequentially a parser, an unparser, a parser and an unparser, and assert that both
// outputs from the unparsers are equal. This verifies that the parser/unparser pair is
// idempotent.
// https://en.wikipedia.org/wiki/Idempotence
// Here, the pair of operations is str::as_bytes(&self) and str::from_utf8(&[u8]).
fn idempotency_fuzz(data: &str) {
    // We have already parsed the data once in the main harness.
    let parsed_once = data;
    let unparsed_once = parsed_once.as_bytes();
    let parsed_twice = std::str::from_utf8(unparsed_once).unwrap();
    let unparsed_twice = parsed_twice.as_bytes();
    assert_eq!(unparsed_once, unparsed_twice);
}

fn main() {
    ziggy::fuzz!(|data: &[u8]| {
        if let Ok(string) = std::str::from_utf8(data) {
            invariant_fuzz(string);
            differential_fuzz(string);
            correctness_fuzz(string);
            consistency_fuzz(string);
            idempotency_fuzz(string);
            #[cfg(coverage)]
            println!("This is only printed during coverage generation");
        }
    });
}
