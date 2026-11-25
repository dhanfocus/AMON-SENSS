//! Numeric helpers that reproduce the C library / x86-64 semantics the original
//! program relied on, so that the Rust port produces byte-identical output.

fn is_c_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
}

/// `strtol(s, NULL, 10)` on an LP64 system: skips leading whitespace, accepts
/// an optional sign, consumes decimal digits and saturates on overflow.
pub fn strtol(s: &[u8]) -> i64 {
    let mut i = 0;
    while i < s.len() && is_c_space(s[i]) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let limit = i64::MAX as i128 + 1;
    let mut acc: i128 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        acc = (acc * 10 + (s[i] - b'0') as i128).min(limit);
        i += 1;
    }
    let v = if neg { -acc } else { acc };
    v.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// glibc `atoi`, which is `(int) strtol(s, NULL, 10)`.
pub fn atoi(s: &[u8]) -> i32 {
    strtol(s) as i32
}

/// `strtod(s, NULL)` for the decimal forms that appear in configuration files.
pub fn strtod(s: &str) -> f64 {
    let s = s.trim_start_matches(|c: char| c.is_ascii() && is_c_space(c as u8));
    let b = s.as_bytes();
    let mut i = 0;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let lower = s[i..].to_ascii_lowercase();
    for word in ["infinity", "inf", "nan"] {
        if lower.starts_with(word) {
            return s[..i + word.len()].parse().unwrap_or(0.0);
        }
    }
    let digits_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i < b.len() && b[i] == b'.' {
        i += 1;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
    }
    let mantissa = &s[digits_start..i];
    if mantissa.is_empty() || mantissa == "." {
        return 0.0;
    }
    // Optional exponent, only if it is well-formed.
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        let mut j = i + 1;
        if j < b.len() && (b[j] == b'+' || b[j] == b'-') {
            j += 1;
        }
        let exp_digits = j;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j > exp_digits {
            i = j;
        }
    }
    s[..i].parse().unwrap_or(0.0)
}

/// `(int) x` as compiled for x86-64 (`cvttsd2si`): truncation toward zero, and
/// the "integer indefinite" value `INT_MIN` for NaN or out-of-range input.
pub fn cvt_i32(x: f64) -> i32 {
    let t = x.trunc();
    if t.is_nan() || !(-2147483648.0..2147483648.0).contains(&t) {
        i32::MIN
    } else {
        t as i32
    }
}

/// `(long) x` as compiled for x86-64; see [`cvt_i32`].
pub fn cvt_i64(x: f64) -> i64 {
    let t = x.trunc();
    if t.is_nan() || !(-9223372036854775808.0..9223372036854775808.0).contains(&t) {
        i64::MIN
    } else {
        t as i64
    }
}

fn strip_fraction_zeros(s: &str) -> &str {
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.')
    } else {
        s
    }
}

/// Format like C++ `ostream << double` with default flags, i.e. `printf("%g")`
/// with precision 6. Used for `as.dump` compatibility.
pub fn fmt_g(x: f64) -> String {
    if x.is_nan() {
        return if x.is_sign_negative() { "-nan" } else { "nan" }.to_string();
    }
    if x.is_infinite() {
        return if x < 0.0 { "-inf" } else { "inf" }.to_string();
    }
    if x == 0.0 {
        return if x.is_sign_negative() { "-0" } else { "0" }.to_string();
    }
    let sci = format!("{:.5e}", x);
    let (mant, exp) = sci.split_once('e').expect("exponent");
    let exp: i32 = exp.parse().expect("exponent value");
    if !(-4..6).contains(&exp) {
        format!(
            "{}e{}{:02}",
            strip_fraction_zeros(mant),
            if exp < 0 { '-' } else { '+' },
            exp.abs()
        )
    } else {
        let fixed = format!("{:.*}", (5 - exp) as usize, x);
        strip_fraction_zeros(&fixed).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strtol_like_c() {
        assert_eq!(strtol(b"  42xyz"), 42);
        assert_eq!(strtol(b"-17"), -17);
        assert_eq!(strtol(b"+5"), 5);
        assert_eq!(strtol(b""), 0);
        assert_eq!(strtol(b"abc"), 0);
        assert_eq!(strtol(b"2379511808|44694"), 2379511808);
        assert_eq!(strtol(b"99999999999999999999999"), i64::MAX);
        assert_eq!(strtol(b"-99999999999999999999999"), i64::MIN);
        assert_eq!(strtol(b"40\n"), 40);
    }

    #[test]
    fn atoi_truncates_like_glibc() {
        assert_eq!(atoi(b"2792759296"), 2792759296u32 as i32);
        assert_eq!(atoi(b"65535") as i16, -1);
    }

    #[test]
    fn strtod_prefixes() {
        assert_eq!(strtod("3"), 3.0);
        assert_eq!(strtod("0.25"), 0.25);
        assert_eq!(strtod(" 1e3x"), 1000.0);
        assert_eq!(strtod("1e"), 1.0);
        assert_eq!(strtod("-.5"), -0.5);
        assert_eq!(strtod("abc"), 0.0);
        assert_eq!(strtod(""), 0.0);
    }

    #[test]
    fn cvt_matches_x86() {
        assert_eq!(cvt_i32(3.9), 3);
        assert_eq!(cvt_i32(-3.9), -3);
        assert_eq!(cvt_i32(f64::NAN), i32::MIN);
        assert_eq!(cvt_i32(3e9), i32::MIN);
        assert_eq!(cvt_i32(-2147483648.5), i32::MIN);
        assert_eq!(cvt_i64(f64::NAN), i64::MIN);
        assert_eq!(cvt_i64(1.6e9), 1_600_000_000);
    }

    #[test]
    fn fmt_g_matches_printf() {
        let cases: &[(f64, &str)] = &[
            (0.0, "0"),
            (1.0, "1"),
            (100.0, "100"),
            (123456.0, "123456"),
            (1234567.0, "1.23457e+06"),
            (999999.5, "1e+06"),
            (0.5, "0.5"),
            (0.0001, "0.0001"),
            (0.00001234, "1.234e-05"),
            (1.0 / 7.0, "0.142857"),
            (-2.5, "-2.5"),
            (1e100, "1e+100"),
            (61.0 / 3.0, "20.3333"),
        ];
        for (x, want) in cases {
            assert_eq!(fmt_g(*x), *want, "formatting {x}");
        }
    }
}
