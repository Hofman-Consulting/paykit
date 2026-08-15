//! ISO 4217 currencies and minor-unit money amounts with checked arithmetic.
//!
//! [`Money`] always stores an amount as an integer count of a currency's
//! *minor units* (e.g. cents for EUR, fils for BHD, whole yen for JPY) so
//! that arithmetic on amounts is exact and never touches floating point.
//! Conversion to and from the decimal strings payment providers speak is
//! done explicitly via [`Money::to_decimal_string`] and
//! [`Money::parse_decimal`], both of which are aware of each currency's
//! ISO 4217 exponent (number of minor-unit digits) instead of assuming two
//! decimal places.
//!
//! # Security
//!
//! [`Money::parse_decimal`] is the boundary where a provider-supplied
//! amount string turns into a value this crate (and its callers) will
//! compare against a stored order total. Every arithmetic step is
//! `checked_*`, so an overflowing input is rejected with an error rather
//! than silently wrapping into a small, plausible-looking amount.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Currencies whose ISO 4217 minor unit has zero digits (e.g. the yen has
/// no subdivision used in everyday transactions).
const ZERO_EXPONENT_CURRENCIES: [&str; 16] = [
    "BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF", "UGX", "VND", "VUV",
    "XAF", "XOF", "XPF",
];

/// Currencies whose ISO 4217 minor unit has three digits (e.g. the Bahraini
/// dinar subdivides into 1000 fils).
const THREE_EXPONENT_CURRENCIES: [&str; 7] = ["BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND"];

/// A 3-letter ISO 4217 currency code (e.g. `EUR`, `USD`).
///
/// Always stored and compared in uppercase. Construct via [`Currency::new`],
/// [`FromStr`], or one of the provided constants.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct Currency([u8; 3]);

impl Currency {
    /// Euro.
    pub const EUR: Currency = Currency([b'E', b'U', b'R']);
    /// United States dollar.
    pub const USD: Currency = Currency([b'U', b'S', b'D']);
    /// Pound sterling.
    pub const GBP: Currency = Currency([b'G', b'B', b'P']);
    /// Japanese yen.
    pub const JPY: Currency = Currency([b'J', b'P', b'Y']);

    /// Parses a 3-letter ISO 4217 currency code, normalizing to uppercase.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCurrencyError`] if `code` is not exactly 3 ASCII
    /// alphabetic characters.
    ///
    /// # Examples
    ///
    /// ```
    /// use paykit::Currency;
    ///
    /// assert_eq!(Currency::new("eur").unwrap(), Currency::EUR);
    /// assert!(Currency::new("E1R").is_err());
    /// assert!(Currency::new("EURO").is_err());
    /// ```
    pub fn new(code: &str) -> Result<Self, ParseCurrencyError> {
        if !code.is_ascii() {
            return Err(ParseCurrencyError::NotAsciiAlphabetic);
        }
        if code.len() != 3 {
            return Err(ParseCurrencyError::InvalidLength(code.len()));
        }
        let bytes = code.as_bytes();
        if !bytes.iter().all(u8::is_ascii_alphabetic) {
            return Err(ParseCurrencyError::NotAsciiAlphabetic);
        }
        Ok(Self([
            bytes[0].to_ascii_uppercase(),
            bytes[1].to_ascii_uppercase(),
            bytes[2].to_ascii_uppercase(),
        ]))
    }

    /// Returns the uppercase 3-letter code, e.g. `"EUR"`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Invariant: `self.0` is always 3 ASCII bytes, set only via `new`
        // (which validates ASCII alphabetic input) or the associated
        // constants above. `unwrap_or_default` is a defensive fallback
        // that is never actually reached, kept panic-free per crate policy.
        std::str::from_utf8(&self.0).unwrap_or_default()
    }

    /// Returns the number of ISO 4217 minor-unit digits for this currency
    /// (e.g. `2` for EUR, `0` for JPY, `3` for BHD). Defaults to `2` for
    /// any currency not in the zero- or three-digit exception tables.
    #[must_use]
    pub fn exponent(&self) -> u32 {
        let code = self.as_str();
        if ZERO_EXPONENT_CURRENCIES.contains(&code) {
            0
        } else if THREE_EXPONENT_CURRENCIES.contains(&code) {
            3
        } else {
            2
        }
    }
}

impl FromStr for Currency {
    type Err = ParseCurrencyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl fmt::Debug for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Currency").field(&self.as_str()).finish()
    }
}

impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Currency {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Currency {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let code = String::deserialize(deserializer)?;
        Self::new(&code).map_err(serde::de::Error::custom)
    }
}

/// Error returned by [`Currency::new`] / [`Currency::from_str`].
///
/// `#[non_exhaustive]`: new variants may be added in a minor release.
/// Existing variants remain directly constructible; only exhaustive
/// matching from outside this crate requires a wildcard arm.
#[derive(Debug, Clone, Eq, PartialEq, Error)]
#[non_exhaustive]
pub enum ParseCurrencyError {
    /// The input was not exactly 3 characters long.
    #[error("currency code must be exactly 3 characters, got {0}")]
    InvalidLength(usize),
    /// The input contained a non-ASCII-alphabetic character (e.g. a digit).
    #[error("currency code must contain only ASCII alphabetic characters")]
    NotAsciiAlphabetic,
}

/// An exact monetary amount, stored as an integer count of a currency's
/// minor units (e.g. cents for EUR).
///
/// `Money` never uses floating point, so equality and arithmetic on the
/// stored amount are exact. Use [`Money::to_decimal_string`] /
/// [`Money::parse_decimal`] to interoperate with the decimal strings
/// payment providers use on the wire.
///
/// # Ordering
///
/// `Money` implements [`PartialOrd`] but deliberately not [`Ord`]:
/// comparing two amounts in different currencies is meaningless without an
/// exchange rate, so [`Money::partial_cmp`](PartialOrd::partial_cmp)
/// returns `None` on a currency mismatch rather than silently comparing
/// raw minor units (which would make e.g. `1 JPY > 100 BHD` compare as
/// `true`). `Ord` requires a total order and has no way to express that
/// "returns `None`" case, so implementing it would force picking between
/// panicking on mismatched currencies or comparing minor units regardless
/// of currency — both worse than making the caller handle mismatch
/// explicitly. Callers that need a total order across mixed currencies
/// must convert to a common currency themselves first.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Money {
    minor_units: i64,
    currency: Currency,
}

impl Money {
    /// Builds a `Money` from a raw minor-unit amount (e.g. cents for EUR).
    #[must_use]
    pub fn from_minor(minor_units: i64, currency: Currency) -> Self {
        Self {
            minor_units,
            currency,
        }
    }

    /// The raw minor-unit amount (e.g. cents for EUR).
    #[must_use]
    pub fn minor_units(&self) -> i64 {
        self.minor_units
    }

    /// The currency this amount is denominated in.
    #[must_use]
    pub fn currency(&self) -> Currency {
        self.currency
    }

    /// Adds two amounts, returning `None` on currency mismatch or overflow.
    #[must_use]
    pub fn checked_add(self, other: Self) -> Option<Self> {
        if self.currency != other.currency {
            return None;
        }
        Some(Self {
            minor_units: self.minor_units.checked_add(other.minor_units)?,
            currency: self.currency,
        })
    }

    /// Subtracts `other` from `self`, returning `None` on currency mismatch
    /// or overflow.
    #[must_use]
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        if self.currency != other.currency {
            return None;
        }
        Some(Self {
            minor_units: self.minor_units.checked_sub(other.minor_units)?,
            currency: self.currency,
        })
    }

    /// Formats the amount as the decimal string payment providers expect,
    /// using the currency's ISO 4217 exponent, e.g. `"10.00"` for EUR or
    /// `"1000"` for JPY.
    ///
    /// # Examples
    ///
    /// ```
    /// use paykit::{Currency, Money};
    ///
    /// assert_eq!(Money::from_minor(1000, Currency::EUR).to_decimal_string(), "10.00");
    /// assert_eq!(Money::from_minor(1000, Currency::JPY).to_decimal_string(), "1000");
    /// ```
    #[must_use]
    pub fn to_decimal_string(&self) -> String {
        let exponent = self.currency.exponent();
        if exponent == 0 {
            return self.minor_units.to_string();
        }

        let scale: u128 = 10u128.checked_pow(exponent).unwrap_or(1);
        let magnitude: u128 = i128::from(self.minor_units).unsigned_abs();
        let whole = magnitude.checked_div(scale).unwrap_or(0);
        let frac = magnitude.checked_rem(scale).unwrap_or(0);
        let sign = if self.minor_units < 0 { "-" } else { "" };
        let width = exponent as usize;

        format!("{sign}{whole}.{frac:0width$}")
    }

    /// Parses a provider-supplied decimal string against a known currency.
    ///
    /// Accepts the grammar `-?\d+(\.\d+)?`: an optional single leading
    /// minus sign, a non-empty run of digits, and an optional fractional
    /// part. Let `N` be the currency's ISO 4217 exponent (0 for JPY, 3 for
    /// BHD, 2 otherwise). A fractional part of up to `N` digits is used
    /// exactly; a fractional part *longer* than `N` digits is tolerated
    /// only when every digit past position `N` is `0` — a harmless
    /// formatting difference some providers emit (e.g. `"10.000"` for EUR,
    /// `"1000.00"` for JPY) — and is truncated to `N` digits before being
    /// interpreted. A fraction that would actually lose precision (e.g.
    /// `"10.999"` for EUR, or `"10.1"` for JPY) is rejected. This
    /// asymmetry is deliberate: outbound ([`Money::to_decimal_string`])
    /// stays exact, but rejecting a harmless trailing-zero formatting
    /// difference on the way *in* would turn it into an unrecoverable
    /// [`crate::Error::Decode`] on a payment that may already be settled.
    ///
    /// All arithmetic is checked; an amount that would overflow an `i64`
    /// is rejected with [`ParseMoneyError::Overflow`] rather than wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`ParseMoneyError`] if `value` does not match the grammar
    /// above, has a fractional digit past the currency's precision that
    /// isn't `0`, or overflows `i64`.
    ///
    /// # Examples
    ///
    /// ```
    /// use paykit::{Currency, Money};
    ///
    /// let money = Money::parse_decimal("10.50", Currency::EUR).unwrap();
    /// assert_eq!(money.minor_units(), 1050);
    ///
    /// // Redundant trailing zeros beyond the currency's precision are
    /// // tolerated on input.
    /// assert_eq!(
    ///     Money::parse_decimal("10.000", Currency::EUR).unwrap().minor_units(),
    ///     1000
    /// );
    ///
    /// assert!(Money::parse_decimal("+5.00", Currency::EUR).is_err());
    /// assert!(Money::parse_decimal("--5.00", Currency::EUR).is_err());
    /// assert!(Money::parse_decimal("10.999", Currency::EUR).is_err());
    /// ```
    pub fn parse_decimal(value: &str, currency: Currency) -> Result<Self, ParseMoneyError> {
        if value.is_empty() {
            return Err(ParseMoneyError::Empty);
        }

        let negative = value.starts_with('-');
        let unsigned = if negative { &value[1..] } else { value };
        if unsigned.is_empty() || unsigned.starts_with('-') {
            return Err(ParseMoneyError::InvalidFormat);
        }

        let mut split = unsigned.splitn(2, '.');
        let int_part = split.next().unwrap_or_default();
        let frac_part = split.next();

        if int_part.is_empty() || !int_part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ParseMoneyError::InvalidFormat);
        }

        let exponent = currency.exponent();

        let frac_digits: &str = match frac_part {
            None => "",
            Some(f) => {
                if f.is_empty() {
                    // Trailing dot with no digits, e.g. "1.".
                    return Err(ParseMoneyError::InvalidFormat);
                }
                if !f.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(ParseMoneyError::InvalidFormat);
                }
                let len = u32::try_from(f.len()).unwrap_or(u32::MAX);
                if len > exponent {
                    // More fractional digits than the currency's precision
                    // allows. Tolerate this when every digit past that
                    // precision is a redundant trailing zero (e.g. "10.000"
                    // for EUR, "1000.00" for JPY) by truncating down to the
                    // significant digits; reject anything that would
                    // actually lose precision.
                    let keep = exponent as usize;
                    let (kept, extra) = f.split_at(keep);
                    if !extra.bytes().all(|b| b == b'0') {
                        return Err(ParseMoneyError::FractionTooLong {
                            currency,
                            max_digits: exponent,
                        });
                    }
                    kept
                } else {
                    f
                }
            }
        };

        // Concatenate the integer and fractional digits into one magnitude,
        // then scale up by whatever's left of the currency's exponent to
        // account for a fraction shorter than the full precision (e.g.
        // "0.5" EUR means 50 cents, not 5).
        let mut magnitude: u128 = 0;
        for b in int_part.bytes().chain(frac_digits.bytes()) {
            let digit = u128::from(b.saturating_sub(b'0'));
            magnitude = magnitude
                .checked_mul(10)
                .and_then(|m| m.checked_add(digit))
                .ok_or(ParseMoneyError::Overflow)?;
        }

        let frac_len = u32::try_from(frac_digits.len()).unwrap_or(0);
        let pad_exponent = exponent.saturating_sub(frac_len);
        let pad = 10u128
            .checked_pow(pad_exponent)
            .ok_or(ParseMoneyError::Overflow)?;
        magnitude = magnitude
            .checked_mul(pad)
            .ok_or(ParseMoneyError::Overflow)?;

        let signed = i128::try_from(magnitude).map_err(|_| ParseMoneyError::Overflow)?;
        let signed = if negative {
            signed.checked_neg().ok_or(ParseMoneyError::Overflow)?
        } else {
            signed
        };

        let minor_units = i64::try_from(signed).map_err(|_| ParseMoneyError::Overflow)?;

        Ok(Self {
            minor_units,
            currency,
        })
    }
}

impl fmt::Display for Money {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.to_decimal_string(), self.currency)
    }
}

impl PartialOrd for Money {
    /// Compares two amounts, or returns `None` if they are in different
    /// currencies. See the "Ordering" section on [`Money`]'s own docs for
    /// why this crate does not implement `Ord`.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.currency != other.currency {
            return None;
        }
        Some(self.minor_units.cmp(&other.minor_units))
    }
}

/// Error returned by [`Money::parse_decimal`].
///
/// `#[non_exhaustive]`: new variants may be added in a minor release.
/// Existing variants remain directly constructible; only exhaustive
/// matching from outside this crate requires a wildcard arm.
#[derive(Debug, Clone, Eq, PartialEq, Error)]
#[non_exhaustive]
pub enum ParseMoneyError {
    /// The input string was empty.
    #[error("value is empty")]
    Empty,
    /// The input did not match the `-?\d+(\.\d+)?` grammar (e.g. a leading
    /// `+`, a repeated sign, whitespace, or a missing integer part).
    #[error("invalid decimal format")]
    InvalidFormat,
    /// The fractional part had a non-zero digit past the currency's ISO
    /// 4217 exponent, i.e. more precision than the currency supports.
    /// Trailing zero digits past that point are tolerated and do not
    /// trigger this error — see [`Money::parse_decimal`].
    #[error("fraction has more significant digits than {currency} allows ({max_digits} max)")]
    FractionTooLong {
        /// The currency the value was parsed against.
        currency: Currency,
        /// The maximum number of fractional digits `currency` permits.
        max_digits: u32,
    },
    /// The amount overflowed `i64` minor units.
    #[error("amount overflows i64 minor units")]
    Overflow,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // A representative currency for each exponent bucket, used by the
    // property test below.
    const CURRENCIES: [Currency; 5] = [
        Currency::EUR,
        Currency::USD,
        Currency::GBP,
        Currency::JPY,                // exponent 0
        Currency([b'B', b'H', b'D']), // exponent 3
    ];

    // --- Currency::new / FromStr ---

    #[test]
    fn currency_new_normalizes_to_uppercase() {
        assert_eq!(Currency::new("eur").unwrap(), Currency::EUR);
        assert_eq!(Currency::new("Eur").unwrap().as_str(), "EUR");
    }

    #[test]
    fn currency_new_rejects_wrong_length() {
        assert_eq!(
            Currency::new("EU").unwrap_err(),
            ParseCurrencyError::InvalidLength(2)
        );
        assert_eq!(
            Currency::new("EURO").unwrap_err(),
            ParseCurrencyError::InvalidLength(4)
        );
    }

    #[test]
    fn currency_new_rejects_empty() {
        assert_eq!(
            Currency::new("").unwrap_err(),
            ParseCurrencyError::InvalidLength(0)
        );
    }

    #[test]
    fn currency_new_rejects_digits() {
        assert_eq!(
            Currency::new("E1R").unwrap_err(),
            ParseCurrencyError::NotAsciiAlphabetic
        );
    }

    #[test]
    fn currency_new_rejects_non_ascii() {
        assert_eq!(
            Currency::new("€UR").unwrap_err(),
            ParseCurrencyError::NotAsciiAlphabetic
        );
    }

    #[test]
    fn currency_from_str_matches_new() {
        assert_eq!("gbp".parse::<Currency>().unwrap(), Currency::GBP);
        assert!("XX".parse::<Currency>().is_err());
    }

    #[test]
    fn currency_display_and_debug() {
        assert_eq!(Currency::EUR.to_string(), "EUR");
        assert_eq!(format!("{:?}", Currency::EUR), "Currency(\"EUR\")");
    }

    #[test]
    fn currency_serde_round_trip() {
        let json = serde_json::to_string(&Currency::EUR).unwrap();
        assert_eq!(json, "\"EUR\"");
        let back: Currency = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Currency::EUR);
    }

    #[test]
    fn currency_serde_rejects_invalid_code() {
        let result: Result<Currency, _> = serde_json::from_str("\"EU\"");
        assert!(result.is_err());
    }

    // --- Money: serde (gated behind the `serde` feature) ---

    #[test]
    #[cfg(feature = "serde")]
    fn money_serde_round_trip() {
        let money = Money::from_minor(1234, Currency::EUR);
        let json = serde_json::to_string(&money).unwrap();
        let back: Money = serde_json::from_str(&json).unwrap();
        assert_eq!(back, money);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn money_serde_round_trip_negative_amount() {
        let money = Money::from_minor(-50, Currency::JPY);
        let json = serde_json::to_string(&money).unwrap();
        let back: Money = serde_json::from_str(&json).unwrap();
        assert_eq!(back, money);
    }

    // --- Currency::exponent ---

    #[test]
    fn exponent_defaults_to_two() {
        assert_eq!(Currency::EUR.exponent(), 2);
        assert_eq!(Currency::USD.exponent(), 2);
        assert_eq!(Currency::GBP.exponent(), 2);
    }

    #[test]
    fn exponent_zero_for_jpy_and_krw() {
        assert_eq!(Currency::JPY.exponent(), 0);
        assert_eq!(Currency::new("KRW").unwrap().exponent(), 0);
    }

    #[test]
    fn exponent_three_for_three_decimal_currencies() {
        for code in ["BHD", "KWD", "JOD", "TND", "OMR"] {
            assert_eq!(Currency::new(code).unwrap().exponent(), 3, "{code}");
        }
    }

    // --- Money::to_decimal_string ---

    #[test]
    fn to_decimal_string_eur_two_decimals() {
        assert_eq!(
            Money::from_minor(1000, Currency::EUR).to_decimal_string(),
            "10.00"
        );
        assert_eq!(
            Money::from_minor(0, Currency::EUR).to_decimal_string(),
            "0.00"
        );
        assert_eq!(
            Money::from_minor(1, Currency::EUR).to_decimal_string(),
            "0.01"
        );
        assert_eq!(
            Money::from_minor(-50, Currency::EUR).to_decimal_string(),
            "-0.50"
        );
    }

    #[test]
    fn to_decimal_string_jpy_zero_decimals() {
        assert_eq!(
            Money::from_minor(1000, Currency::JPY).to_decimal_string(),
            "1000"
        );
        assert_eq!(
            Money::from_minor(-7, Currency::JPY).to_decimal_string(),
            "-7"
        );
    }

    #[test]
    fn to_decimal_string_bhd_three_decimals() {
        let bhd = Currency::new("BHD").unwrap();
        assert_eq!(Money::from_minor(12345, bhd).to_decimal_string(), "12.345");
        assert_eq!(Money::from_minor(5, bhd).to_decimal_string(), "0.005");
    }

    // --- Money::parse_decimal: happy paths ---

    #[test]
    fn parse_decimal_eur_basic() {
        assert_eq!(
            Money::parse_decimal("10.00", Currency::EUR).unwrap(),
            Money::from_minor(1000, Currency::EUR)
        );
        assert_eq!(
            Money::parse_decimal("0.01", Currency::EUR).unwrap(),
            Money::from_minor(1, Currency::EUR)
        );
        assert_eq!(
            Money::parse_decimal("-0.50", Currency::EUR).unwrap(),
            Money::from_minor(-50, Currency::EUR)
        );
    }

    #[test]
    fn parse_decimal_allows_short_fraction() {
        // "10.5" means 50 cents, not 5 — matches to_decimal_string's own output shape.
        assert_eq!(
            Money::parse_decimal("10.5", Currency::EUR).unwrap(),
            Money::from_minor(1050, Currency::EUR)
        );
    }

    #[test]
    fn parse_decimal_jpy_no_fraction() {
        assert_eq!(
            Money::parse_decimal("1000", Currency::JPY).unwrap(),
            Money::from_minor(1000, Currency::JPY)
        );
    }

    #[test]
    fn parse_decimal_bhd_three_digit_fraction() {
        let bhd = Currency::new("BHD").unwrap();
        assert_eq!(
            Money::parse_decimal("12.345", bhd).unwrap(),
            Money::from_minor(12345, bhd)
        );
    }

    // --- Money::parse_decimal: strict grammar rejections ---

    #[test]
    fn parse_decimal_rejects_leading_plus() {
        assert_eq!(
            Money::parse_decimal("+5.00", Currency::EUR),
            Err(ParseMoneyError::InvalidFormat)
        );
    }

    #[test]
    fn parse_decimal_rejects_repeated_sign() {
        assert_eq!(
            Money::parse_decimal("--5.00", Currency::EUR),
            Err(ParseMoneyError::InvalidFormat)
        );
    }

    #[test]
    fn parse_decimal_rejects_empty_string() {
        assert_eq!(
            Money::parse_decimal("", Currency::EUR),
            Err(ParseMoneyError::Empty)
        );
    }

    #[test]
    fn parse_decimal_rejects_whitespace() {
        assert_eq!(
            Money::parse_decimal(" 5.00", Currency::EUR),
            Err(ParseMoneyError::InvalidFormat)
        );
        assert_eq!(
            Money::parse_decimal("5.00 ", Currency::EUR),
            Err(ParseMoneyError::InvalidFormat)
        );
    }

    #[test]
    fn parse_decimal_rejects_empty_integer_part() {
        assert_eq!(
            Money::parse_decimal(".5", Currency::EUR),
            Err(ParseMoneyError::InvalidFormat)
        );
    }

    #[test]
    fn parse_decimal_rejects_trailing_dot() {
        assert_eq!(
            Money::parse_decimal("1.", Currency::EUR),
            Err(ParseMoneyError::InvalidFormat)
        );
    }

    #[test]
    fn parse_decimal_rejects_fraction_longer_than_exponent() {
        assert_eq!(
            Money::parse_decimal("10.999", Currency::EUR),
            Err(ParseMoneyError::FractionTooLong {
                currency: Currency::EUR,
                max_digits: 2,
            })
        );
    }

    #[test]
    fn parse_decimal_rejects_nonzero_fraction_for_zero_exponent_currency() {
        assert_eq!(
            Money::parse_decimal("10.1", Currency::JPY),
            Err(ParseMoneyError::FractionTooLong {
                currency: Currency::JPY,
                max_digits: 0,
            })
        );
    }

    // --- Money::parse_decimal: tolerate redundant trailing zeros on input ---

    #[test]
    fn parse_decimal_accepts_redundant_trailing_zeros_eur() {
        assert_eq!(
            Money::parse_decimal("10.000", Currency::EUR).unwrap(),
            Money::from_minor(1000, Currency::EUR)
        );
        assert_eq!(
            Money::parse_decimal("0.010000", Currency::EUR).unwrap(),
            Money::from_minor(1, Currency::EUR)
        );
    }

    #[test]
    fn parse_decimal_accepts_redundant_trailing_zeros_jpy() {
        // JPY's exponent is 0, so *any* all-zero fraction is redundant.
        assert_eq!(
            Money::parse_decimal("1000.00", Currency::JPY).unwrap(),
            Money::from_minor(1000, Currency::JPY)
        );
        assert_eq!(
            Money::parse_decimal("10.0", Currency::JPY).unwrap(),
            Money::from_minor(10, Currency::JPY)
        );
    }

    #[test]
    fn parse_decimal_still_rejects_a_fraction_that_would_lose_precision() {
        assert_eq!(
            Money::parse_decimal("10.999", Currency::EUR),
            Err(ParseMoneyError::FractionTooLong {
                currency: Currency::EUR,
                max_digits: 2,
            })
        );
        assert_eq!(
            Money::parse_decimal("10.001", Currency::EUR),
            Err(ParseMoneyError::FractionTooLong {
                currency: Currency::EUR,
                max_digits: 2,
            })
        );
    }

    // --- Money::parse_decimal: overflow safety (the reason this file exists) ---

    #[test]
    fn parse_decimal_rejects_overflow_instead_of_wrapping() {
        // The vulnerability being fixed: the old `whole * 100 + frac` used
        // plain, unchecked i64 arithmetic. In a release build that wraps
        // instead of panicking. Demonstrate the wraparound with the exact
        // failure mode, then prove the new parser refuses it outright.
        let whole = i64::MAX / 50; // parses fine as a bare i64 on its own.
        let naive_wrapped = whole.wrapping_mul(100);
        assert_eq!(
            naive_wrapped, -16,
            "sanity check: naive unchecked math wraps this huge amount into a tiny, \
             entirely plausible-looking one"
        );

        let crafted = format!("{whole}.00");
        let result = Money::parse_decimal(&crafted, Currency::EUR);
        assert_eq!(
            result,
            Err(ParseMoneyError::Overflow),
            "an overflowing amount must be rejected, not silently wrapped to {naive_wrapped}"
        );
    }

    #[test]
    fn parse_decimal_rejects_absurdly_long_digit_strings() {
        let huge = "9".repeat(60);
        assert_eq!(
            Money::parse_decimal(&huge, Currency::EUR),
            Err(ParseMoneyError::Overflow)
        );
    }

    #[test]
    fn parse_decimal_rejects_i64_min_magnitude_minus_one() {
        // One past what i64 can represent as a negative amount.
        assert_eq!(
            Money::parse_decimal("-9223372036854775809", Currency::JPY),
            Err(ParseMoneyError::Overflow)
        );
    }

    // --- Money round-trip: explicit edge cases ---

    #[test]
    fn round_trip_i64_max_and_min_eur() {
        for minor in [i64::MAX, i64::MIN, 0, -1, 1] {
            let money = Money::from_minor(minor, Currency::EUR);
            let parsed = Money::parse_decimal(&money.to_decimal_string(), Currency::EUR).unwrap();
            assert_eq!(parsed, money, "round-trip failed for {minor}");
        }
    }

    #[test]
    fn round_trip_i64_max_and_min_jpy() {
        for minor in [i64::MAX, i64::MIN, 0] {
            let money = Money::from_minor(minor, Currency::JPY);
            let parsed = Money::parse_decimal(&money.to_decimal_string(), Currency::JPY).unwrap();
            assert_eq!(parsed, money, "round-trip failed for {minor}");
        }
    }

    #[test]
    fn round_trip_i64_max_and_min_bhd() {
        let bhd = Currency::new("BHD").unwrap();
        for minor in [i64::MAX, i64::MIN, 0] {
            let money = Money::from_minor(minor, bhd);
            let parsed = Money::parse_decimal(&money.to_decimal_string(), bhd).unwrap();
            assert_eq!(parsed, money, "round-trip failed for {minor}");
        }
    }

    // --- Money::checked_add / checked_sub ---

    #[test]
    fn checked_add_same_currency() {
        let a = Money::from_minor(100, Currency::EUR);
        let b = Money::from_minor(50, Currency::EUR);
        assert_eq!(
            a.checked_add(b),
            Some(Money::from_minor(150, Currency::EUR))
        );
    }

    #[test]
    fn checked_add_currency_mismatch_returns_none() {
        let a = Money::from_minor(100, Currency::EUR);
        let b = Money::from_minor(50, Currency::USD);
        assert_eq!(a.checked_add(b), None);
    }

    #[test]
    fn checked_add_overflow_returns_none() {
        let a = Money::from_minor(i64::MAX, Currency::EUR);
        let b = Money::from_minor(1, Currency::EUR);
        assert_eq!(a.checked_add(b), None);
    }

    #[test]
    fn checked_sub_same_currency() {
        let a = Money::from_minor(100, Currency::EUR);
        let b = Money::from_minor(50, Currency::EUR);
        assert_eq!(a.checked_sub(b), Some(Money::from_minor(50, Currency::EUR)));
    }

    #[test]
    fn checked_sub_overflow_returns_none() {
        let a = Money::from_minor(i64::MIN, Currency::EUR);
        let b = Money::from_minor(1, Currency::EUR);
        assert_eq!(a.checked_sub(b), None);
    }

    #[test]
    fn checked_sub_currency_mismatch_returns_none() {
        let a = Money::from_minor(100, Currency::EUR);
        let b = Money::from_minor(50, Currency::USD);
        assert_eq!(a.checked_sub(b), None);
    }

    // --- Money::PartialOrd ---

    #[test]
    fn partial_cmp_orders_same_currency_amounts() {
        let a = Money::from_minor(100, Currency::EUR);
        let b = Money::from_minor(150, Currency::EUR);
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a.partial_cmp(&a), Some(Ordering::Equal));
    }

    #[test]
    fn partial_cmp_currency_mismatch_returns_none() {
        let a = Money::from_minor(100, Currency::EUR);
        let b = Money::from_minor(100, Currency::USD);
        // `None` means "incomparable", not "equal" — check the method
        // directly rather than `<`/`>`/`<=`/`>=`, which would coerce a
        // `None` into `false` and hide the distinction.
        assert_eq!(a.partial_cmp(&b), None);
    }

    // --- Money::Display ---

    #[test]
    fn money_display_format() {
        assert_eq!(
            Money::from_minor(1000, Currency::EUR).to_string(),
            "10.00 EUR"
        );
        assert_eq!(
            Money::from_minor(1000, Currency::JPY).to_string(),
            "1000 JPY"
        );
    }

    // --- Property: parse_decimal(to_decimal_string(m)) == m ---

    proptest! {
        #[test]
        fn round_trip_arbitrary_amounts(minor in any::<i64>(), idx in 0usize..CURRENCIES.len()) {
            let currency = CURRENCIES[idx];
            let money = Money::from_minor(minor, currency);
            let decimal = money.to_decimal_string();
            let parsed = Money::parse_decimal(&decimal, currency).unwrap();
            prop_assert_eq!(parsed, money);
        }

        #[test]
        fn parse_decimal_never_panics_on_arbitrary_input(value in ".{0,40}") {
            // Whatever garbage comes in, parse_decimal must return a Result,
            // never panic — this is the availability guarantee for a
            // payments library.
            let _ = Money::parse_decimal(&value, Currency::EUR);
        }
    }
}
