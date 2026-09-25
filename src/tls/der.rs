//! The few DER/PEM operations the certificate layer needs, without a general X.509 stack.
//!
//! Only certificates this process generated, loaded from its own store, or received from its
//! own ACME order pass through here. X.509 is always definite-length DER, so only short- and
//! long-form lengths are handled.

use std::num::Wrapping;
use std::time::{Duration, SystemTime};

/// Reads one DER TLV starting at `pos`, returning `(tag, content, end)` where
/// `end` is the offset in `buf` just past the whole TLV (header + content).
fn read_tlv(buf: &[u8], pos: usize) -> Result<(u8, &[u8], usize), &'static str> {
    let tag = *buf.get(pos).ok_or("truncated DER: missing tag")?;
    let pos_plus_1 = pos.checked_add(1).ok_or("DER offset overflow")?;
    let len_byte = *buf.get(pos_plus_1).ok_or("truncated DER: missing length")?;
    let (len, header_len) = if len_byte & 0x80 == 0 {
        (usize::from(len_byte), 2usize)
    } else {
        // Long form: low 7 bits count the number of following length bytes.
        // Real certificates never need more than a couple of these (a cert
        // would have to be >16 MiB to need a 3rd byte); cap at 4 bytes (up
        // to a 4 GiB length) purely as a sanity bound against malformed input.
        let n = usize::from(len_byte & 0x7f);
        if n == 0 || n > 4 {
            return Err("unsupported DER length encoding");
        }
        let start = pos.checked_add(2).ok_or("DER offset overflow")?;
        let end = start.checked_add(n).ok_or("DER offset overflow")?;
        let bytes = buf
            .get(start..end)
            .ok_or("truncated DER: missing length bytes")?;
        // `checked_mul`, not `checked_shl`: a shift only reports shifting by more bits
        // than the type has, not shifting significant bits off the top — so on 32-bit a
        // 4-byte length would wrap to something plausible.
        let mut len = 0usize;
        for &b in bytes {
            len = len
                .checked_mul(256)
                .and_then(|v| v.checked_add(usize::from(b)))
                .ok_or("DER length overflow")?;
        }
        (len, 2usize.checked_add(n).ok_or("DER offset overflow")?)
    };
    let content_start = pos.checked_add(header_len).ok_or("DER offset overflow")?;
    let content_end = content_start
        .checked_add(len)
        .ok_or("DER length overflow")?;
    let content = buf
        .get(content_start..content_end)
        .ok_or("truncated DER: content shorter than declared length")?;
    Ok((tag, content, content_end))
}

const TAG_SEQUENCE: u8 = 0x30;
const TAG_INTEGER: u8 = 0x02;
const TAG_CONTEXT_0: u8 = 0xA0;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;

/// Extracts `TBSCertificate.validity.notAfter` from a DER-encoded X.509 certificate.
pub(crate) fn parse_not_after(cert_der: &[u8]) -> Result<SystemTime, &'static str> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (tag, cert_content, _) = read_tlv(cert_der, 0)?;
    if tag != TAG_SEQUENCE {
        return Err("not a DER SEQUENCE (Certificate)");
    }
    // TBSCertificate ::= SEQUENCE { version?, serialNumber, signature, issuer, validity, ... }
    let (tag, tbs, _) = read_tlv(cert_content, 0)?;
    if tag != TAG_SEQUENCE {
        return Err("not a DER SEQUENCE (TBSCertificate)");
    }

    // Optional `[0] EXPLICIT Version` — present on v3 certs, absent on v1.
    let (tag, _, next) = read_tlv(tbs, 0)?;
    let pos = if tag == TAG_CONTEXT_0 { next } else { 0 };

    // serialNumber INTEGER
    let (tag, _, pos) = read_tlv(tbs, pos)?;
    if tag != TAG_INTEGER {
        return Err("expected serialNumber INTEGER");
    }
    // signature AlgorithmIdentifier ::= SEQUENCE
    let (tag, _, pos) = read_tlv(tbs, pos)?;
    if tag != TAG_SEQUENCE {
        return Err("expected signature AlgorithmIdentifier SEQUENCE");
    }
    // issuer Name ::= SEQUENCE
    let (tag, _, pos) = read_tlv(tbs, pos)?;
    if tag != TAG_SEQUENCE {
        return Err("expected issuer Name SEQUENCE");
    }
    // validity Validity ::= SEQUENCE { notBefore, notAfter }
    let (tag, validity, _) = read_tlv(tbs, pos)?;
    if tag != TAG_SEQUENCE {
        return Err("expected validity SEQUENCE");
    }

    // notBefore Time — skip.
    let (_, _, pos) = read_tlv(validity, 0)?;
    // notAfter Time — decode.
    let (tag, time, _) = read_tlv(validity, pos)?;
    match tag {
        TAG_UTC_TIME => parse_utc_time(time),
        TAG_GENERALIZED_TIME => parse_generalized_time(time),
        _ => Err("notAfter is neither UTCTime nor GeneralizedTime"),
    }
}

fn parse_utc_time(b: &[u8]) -> Result<SystemTime, &'static str> {
    // UTCTime, RFC 5280 profile: `YYMMDDHHMMSSZ` — always UTC, always seconds, always `Z`.
    if b.len() != 13 || b.get(12) != Some(&b'Z') {
        return Err("malformed UTCTime");
    }
    // RFC 5280's Y2K pivot rule: YY >= 50 means 19YY, otherwise 20YY.
    let yy = two_digits(b.get(0..2).ok_or("malformed UTCTime")?)?;
    let year = i64::from(if yy >= 50 {
        (Wrapping(1900u32) + Wrapping(yy)).0
    } else {
        (Wrapping(2000u32) + Wrapping(yy)).0
    });
    ymdhms_to_system_time(
        year,
        two_digits(b.get(2..4).ok_or("malformed UTCTime")?)?,
        two_digits(b.get(4..6).ok_or("malformed UTCTime")?)?,
        two_digits(b.get(6..8).ok_or("malformed UTCTime")?)?,
        two_digits(b.get(8..10).ok_or("malformed UTCTime")?)?,
        two_digits(b.get(10..12).ok_or("malformed UTCTime")?)?,
    )
}

fn parse_generalized_time(b: &[u8]) -> Result<SystemTime, &'static str> {
    // GeneralizedTime, RFC 5280 profile: `YYYYMMDDHHMMSSZ` — no fractional seconds.
    if b.len() != 15 || b.get(14) != Some(&b'Z') {
        return Err("malformed GeneralizedTime");
    }
    let century = two_digits(b.get(0..2).ok_or("malformed GeneralizedTime")?)?;
    let year_in_century = two_digits(b.get(2..4).ok_or("malformed GeneralizedTime")?)?;
    // Bounded, range-checked two-digit groups — see the `Wrapping` note on `two_digits`.
    let year = i64::from((Wrapping(century) * Wrapping(100) + Wrapping(year_in_century)).0);
    ymdhms_to_system_time(
        year,
        two_digits(b.get(4..6).ok_or("malformed GeneralizedTime")?)?,
        two_digits(b.get(6..8).ok_or("malformed GeneralizedTime")?)?,
        two_digits(b.get(8..10).ok_or("malformed GeneralizedTime")?)?,
        two_digits(b.get(10..12).ok_or("malformed GeneralizedTime")?)?,
        two_digits(b.get(12..14).ok_or("malformed GeneralizedTime")?)?,
    )
}

fn two_digits(b: &[u8]) -> Result<u32, &'static str> {
    let [hi, lo] = *b else {
        return Err("expected two ASCII digits");
    };
    if !hi.is_ascii_digit() || !lo.is_ascii_digit() {
        return Err("expected two ASCII digits");
    }
    // `Wrapping`, not raw `-`/`*`/`+`: the digits are already range-checked above so this
    // never actually wraps, but `clippy::arithmetic_side_effects` doesn't know that and
    // `Wrapping` is its documented way to say "this is deliberate, bounded arithmetic".
    let hi = Wrapping(u32::from(hi)) - Wrapping(u32::from(b'0'));
    let lo = Wrapping(u32::from(lo)) - Wrapping(u32::from(b'0'));
    Ok((hi * Wrapping(10) + lo).0)
}

/// Converts a UTC calendar date/time (as decoded from DER) into a `SystemTime`,
/// using the standard proleptic-Gregorian civil-calendar-to-days-since-epoch
/// formula (Howard Hinnant's `days_from_civil`, a widely published public-domain
/// algorithm — not copied from any particular implementation).
fn ymdhms_to_system_time(
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Result<SystemTime, &'static str> {
    let leap_year =
        year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return Err("month/day out of range"),
    };
    if day == 0 || day > days_in_month {
        return Err("month/day out of range");
    }
    if hour > 23 || minute > 59 || second > 60 {
        return Err("time-of-day out of range");
    }
    let days = days_from_civil(year, i64::from(month), i64::from(day));
    // Bounded by the `hour`/`minute`/`second` checks above — see `two_digits` for why
    // `Wrapping` rather than raw arithmetic.
    let secs_of_day = (Wrapping(i64::from(hour)) * Wrapping(3600)
        + Wrapping(i64::from(minute)) * Wrapping(60)
        + Wrapping(i64::from(second)))
    .0;
    let total_secs = days
        .checked_mul(86_400)
        .and_then(|d| d.checked_add(secs_of_day))
        .ok_or("date arithmetic overflow")?;
    // Certificates with a notAfter before 1970 aren't something we can (or need
    // to) support: we only ever compare this against `SystemTime::now()`.
    let total_secs = u64::try_from(total_secs).map_err(|_| "date before the Unix epoch")?;
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(total_secs))
        .ok_or("date arithmetic overflow")
}

/// Days since 1970-01-01 for a given proleptic-Gregorian civil date.
///
/// Uses `Wrapping` throughout — see `two_digits` for why — rather than raw arithmetic: the
/// month/day range is validated by `ymdhms_to_system_time` before this is ever called, and
/// the year range certificates can express (four-digit `GeneralizedTime`/two-digit
/// `UTCTime` years) is nowhere near enough to overflow `i64`, so this never actually wraps.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let (y, m, d) = (Wrapping(y), Wrapping(m), Wrapping(d));
    let y = if m.0 <= 2 { y - Wrapping(1) } else { y };
    let era = Wrapping(if y.0 >= 0 { y.0 } else { (y - Wrapping(399)).0 } / 400);
    let yoe = y - era * Wrapping(400); // [0, 399]
    let mp = Wrapping((m + Wrapping(9)).0 % 12); // [0, 11], Mar=0 .. Feb=11
    let doy = Wrapping((mp * Wrapping(153) + Wrapping(2)).0 / 5) + d - Wrapping(1); // [0, 365]
    let doe = yoe * Wrapping(365) + Wrapping(yoe.0 / 4) - Wrapping(yoe.0 / 100) + doy; // [0, 146096]
    (era * Wrapping(146_097) + doe - Wrapping(719_468)).0
}

/// Encodes DER as one PEM block (RFC 7468 §2: 64-column base64 lines).
pub(crate) fn pem_encode(label: &str, der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut base64 = Vec::with_capacity(der.len().div_ceil(3).saturating_mul(4));
    for chunk in der.chunks(3) {
        let byte = |i| chunk.get(i).copied().unwrap_or(0);
        let group = u32::from_be_bytes([0, byte(0), byte(1), byte(2)]);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            let sextet = usize::try_from((group >> shift) & 0x3f).unwrap_or(0);
            base64.push(if i > chunk.len() {
                b'='
            } else {
                ALPHABET.get(sextet).copied().unwrap_or(b'=')
            });
        }
    }
    let mut pem = format!("-----BEGIN {label}-----\n");
    for line in base64.chunks(64) {
        pem.push_str(&String::from_utf8_lossy(line));
        pem.push('\n');
    }
    pem + "-----END " + label + "-----\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_day_zero() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
    }

    #[test]
    fn known_dates() {
        // 2024-01-01 is 19723 days after the epoch.
        assert_eq!(days_from_civil(2024, 1, 1), 19723);
        // Leap-day handling: 2024 is a leap year, so 2024-02-29 exists.
        assert_eq!(
            days_from_civil(2024, 3, 1) - days_from_civil(2024, 2, 29),
            1
        );
    }

    #[test]
    fn utc_time_roundtrip() {
        let t = parse_utc_time(b"991231235959Z").unwrap();
        let secs = t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        // 1999-12-31 23:59:59 UTC
        assert_eq!(secs, 946_684_799);
    }

    #[test]
    fn utc_time_y2k_pivot() {
        // "49" -> 2049 (post-epoch, decodable); "50" -> 1950 (pre-epoch, rejected
        // by design — see `ymdhms_to_system_time`).
        assert!(parse_utc_time(b"490101000000Z").is_ok());
        assert!(parse_utc_time(b"500101000000Z").is_err());
    }

    #[test]
    fn generalized_time_roundtrip() {
        let t = parse_generalized_time(b"20991231235959Z").unwrap();
        let secs = t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 4_102_444_799);
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(parse_utc_time(b"not-a-time!!!").is_err());
        assert!(parse_utc_time(b"230229000000Z").is_err());
        assert!(parse_utc_time(b"240230000000Z").is_err());
        assert!(parse_generalized_time(b"short").is_err());
        assert!(parse_generalized_time(b"21000229000000Z").is_err());
        assert!(parse_not_after(b"").is_err());
        assert!(parse_not_after(&[0x30, 0x00]).is_err());
    }

    /// End-to-end: the full DER walk (`SEQUENCE` -> `TBSCertificate` -> ... -> `Validity` ->
    /// `notAfter`) over a real `rcgen` certificate lands on a sane result.
    #[test]
    fn parses_notafter_from_a_real_certificate() {
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        // rcgen's default `not_after` is far in the future (year 4096) — check
        // we land somewhere plausible rather than pinning the exact instant, so
        // this test isn't fragile to rcgen ever changing its default.
        let parsed = parse_not_after(cert.der().as_ref()).unwrap();
        let year_2170 = SystemTime::UNIX_EPOCH + Duration::from_hours(24 * 365 * 200);
        assert!(
            parsed > year_2170,
            "expected a far-future notAfter, got {parsed:?}"
        );
    }

    /// Both padding cases, plus random real certificates checked against rcgen's own PEM.
    #[test]
    fn pem_encoding_matches_rcgen() {
        for _ in 0..3 {
            let name = format!("{}.example", rand::random::<u32>());
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            let cert = rcgen::CertificateParams::new(vec![name])
                .unwrap()
                .self_signed(&key)
                .unwrap();
            assert_eq!(
                pem_encode("CERTIFICATE", cert.der()).replace('\n', ""),
                cert.pem().replace(['\r', '\n'], "")
            );
        }
        assert_eq!(
            pem_encode("X", b"ab"),
            "-----BEGIN X-----\nYWI=\n-----END X-----\n"
        );
        assert_eq!(
            pem_encode("X", b"a"),
            "-----BEGIN X-----\nYQ==\n-----END X-----\n"
        );
    }
}
