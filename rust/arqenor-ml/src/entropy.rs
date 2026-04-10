//! Shannon entropy calculation for byte sequences.

/// Compute Shannon entropy (bits per byte) of a byte slice.
///
/// Returns 0.0 for empty input, max ~8.0 for perfectly random data.
/// Used to detect packed/encrypted PE sections — legitimate code typically
/// has entropy in the 5.0–6.5 range, while encrypted/compressed data
/// exceeds 7.0.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn uniform_single_byte_returns_zero() {
        let data = vec![0xAA; 1024];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn two_equally_distributed_bytes() {
        let mut data = vec![0u8; 1000];
        for i in 0..500 {
            data[i] = 0;
        }
        for i in 500..1000 {
            data[i] = 1;
        }
        let e = shannon_entropy(&data);
        assert!((e - 1.0).abs() < 0.01, "expected ~1.0, got {e}");
    }

    #[test]
    fn high_entropy_random_data() {
        // All 256 byte values equally distributed
        let mut data = Vec::with_capacity(256 * 100);
        for _ in 0..100 {
            for b in 0u8..=255 {
                data.push(b);
            }
        }
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01, "expected ~8.0, got {e}");
    }
}
