use abc_probe::bounded_add;

#[test]
fn matches_widened_arithmetic_at_word_boundaries() {
    let boundaries = [0, 1, 255, 256, 1 << 31, u32::MAX - 1, u32::MAX];
    let mut checked = 0;
    for left in boundaries {
        for right in boundaries {
            let expected = u64::from(left) + u64::from(right);
            if let Ok(expected) = u32::try_from(expected) {
                assert_eq!(bounded_add(left, right), expected);
                checked += 1;
            }
        }
    }
    assert!(checked > 0);
}
