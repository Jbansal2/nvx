//! Kernel command-line tokens through which the host configures the guest agent at boot.

use super::{MAX_HOST_MAPPINGS, ProtocolError, violation};

/// Prefix of the token that announces how many host mappings the guest agent receives through
/// `MAPS` requests, such as `nvx_maps=3`. The agent refuses workloads until it has mounted that
/// many.
pub const MAPS_TOKEN: &str = "nvx_maps=";

/// Token with which the guest creates an account for the workload identity when its image lacks
/// a usable one.
pub const WORKLOAD_ACCOUNT_TOKEN: &str = "nvx_workload_account=create";

/// Parses the `nvx_maps=COUNT` token from a Linux kernel command line.
///
/// No token announces zero mappings. One token may contain only decimal digits and must name a
/// count from 1 through [`MAX_HOST_MAPPINGS`]. A duplicate or malformed `nvx_maps=` token is an
/// error. Retired `nvx_map=` tokens are unrelated and are ignored.
pub fn parse_host_mapping_count(command_line: &[u8]) -> Result<u32, ProtocolError> {
    let mut count = 0;
    let mut found = false;
    for token in command_line.split(|byte| matches!(byte, b' ' | b'\t' | b'\n')) {
        let Some(digits) = token.strip_prefix(MAPS_TOKEN.as_bytes()) else {
            continue;
        };
        if found || digits.is_empty() {
            return Err(violation(
                "the nvx_maps kernel parameter is malformed or repeated",
            ));
        }
        let mut value = 0u32;
        for &digit in digits {
            if !digit.is_ascii_digit() || value > MAX_HOST_MAPPINGS as u32 {
                return Err(violation("the nvx_maps kernel parameter is malformed"));
            }
            value = value * 10 + u32::from(digit - b'0');
        }
        if value == 0 || value > MAX_HOST_MAPPINGS as u32 {
            return Err(violation(format!(
                "the nvx_maps kernel parameter must be from 1 through {MAX_HOST_MAPPINGS}"
            )));
        }
        count = value;
        found = true;
    }
    Ok(count)
}
