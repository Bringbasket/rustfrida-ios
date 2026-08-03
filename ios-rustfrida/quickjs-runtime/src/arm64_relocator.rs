use common::{Error, Result};

pub const MAX_ARM64_RELOCATION_INSTRUCTIONS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arm64RelocationKind {
    Unknown,
    Branch,
    BranchLink,
    ConditionalBranch,
    CompareAndBranchZero,
    CompareAndBranchNonZero,
    TestBitAndBranchZero,
    TestBitAndBranchNonZero,
    BranchRegister,
    BranchLinkRegister,
    Return,
    Address,
    AddressPage,
    LoadLiteral,
    LoadSignedWordLiteral,
    LoadFloatingLiteral,
    PrefetchLiteral,
    Other,
}

impl Arm64RelocationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Branch => "b",
            Self::BranchLink => "bl",
            Self::ConditionalBranch => "b.cond",
            Self::CompareAndBranchZero => "cbz",
            Self::CompareAndBranchNonZero => "cbnz",
            Self::TestBitAndBranchZero => "tbz",
            Self::TestBitAndBranchNonZero => "tbnz",
            Self::BranchRegister => "br",
            Self::BranchLinkRegister => "blr",
            Self::Return => "ret",
            Self::Address => "adr",
            Self::AddressPage => "adrp",
            Self::LoadLiteral => "ldr-literal",
            Self::LoadSignedWordLiteral => "ldrsw-literal",
            Self::LoadFloatingLiteral => "ldr-literal-fp",
            Self::PrefetchLiteral => "prfm-literal",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arm64RelocationInfo {
    pub kind: Arm64RelocationKind,
    pub target: Option<u64>,
    pub pc_relative: bool,
    pub condition: Option<u32>,
    pub register: Option<i32>,
    pub bit: Option<u32>,
    pub destination_register: Option<i32>,
    pub signed_load: bool,
    pub floating_size: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arm64DirectRelocationStatus {
    Copied,
    Relocated,
    OutOfRange,
}

impl Arm64DirectRelocationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Copied => "copied",
            Self::Relocated => "relocated",
            Self::OutOfRange => "out-of-range",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arm64RelocationEntry {
    pub source_address: u64,
    pub destination_address: u64,
    pub original_word: u32,
    pub relocated_word: Option<u32>,
    pub info: Arm64RelocationInfo,
    pub status: Arm64DirectRelocationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arm64RelocationPlan {
    pub source_start: u64,
    pub destination_start: u64,
    pub entries: Vec<Arm64RelocationEntry>,
    pub output: Option<Vec<u8>>,
}

impl Arm64RelocationPlan {
    pub const fn directly_relocatable(&self) -> bool {
        self.output.is_some()
    }

    pub const fn requires_fallback(&self) -> bool {
        !self.directly_relocatable()
    }
}

#[cfg(quickjs_arm64_relocator)]
#[repr(C)]
#[derive(Clone, Copy)]
struct RawArm64RelocationInfo {
    kind: u32,
    target: u64,
    pc_relative: i32,
    condition: i32,
    register: i32,
    bit: u32,
    destination_register: i32,
    signed_load: i32,
    floating_size: i32,
}

#[cfg(quickjs_arm64_relocator)]
unsafe extern "C" {
    fn rf_arm64_relocator_analyze(pc: u64, instruction: u32, output: *mut RawArm64RelocationInfo) -> i32;
    fn rf_arm64_relocator_relocate_direct(
        source_pc: u64,
        destination_pc: u64,
        instruction: u32,
        relocated_instruction: *mut u32,
    ) -> i32;
}

pub const fn arm64_relocator_available() -> bool {
    cfg!(quickjs_arm64_relocator)
}

pub fn analyze_arm64_instruction(address: u64, word: u32) -> Result<Arm64RelocationInfo> {
    validate_code_address(address, "ARM64 instruction address")?;

    #[cfg(quickjs_arm64_relocator)]
    {
        let mut raw = RawArm64RelocationInfo {
            kind: 0,
            target: 0,
            pc_relative: 0,
            condition: 0,
            register: 0,
            bit: 0,
            destination_register: 0,
            signed_load: 0,
            floating_size: 0,
        };
        let result = unsafe { rf_arm64_relocator_analyze(address, word, &mut raw) };
        if result != 0 {
            return Err(Error::State("ARM64 relocator analysis failed".into()));
        }
        let info = relocation_info_from_raw(raw);
        if let Some(target) = info.target {
            validate_signed_address(target, "ARM64 PC-relative target")?;
        }
        Ok(info)
    }

    #[cfg(not(quickjs_arm64_relocator))]
    {
        let _ = word;
        Err(Error::Unsupported(
            "ARM64 relocation planning is not compiled for this runtime target".into(),
        ))
    }
}

pub fn plan_arm64_relocation(bytes: &[u8], source_start: u64, destination_start: u64) -> Result<Arm64RelocationPlan> {
    validate_relocation_input(bytes, source_start, destination_start)?;

    #[cfg(quickjs_arm64_relocator)]
    {
        let instruction_count = bytes.len() / 4;
        let mut entries = Vec::with_capacity(instruction_count);
        let mut output = Vec::with_capacity(bytes.len());
        let mut complete = true;

        for (index, chunk) in bytes.chunks_exact(4).enumerate() {
            let offset = u64::try_from(index)
                .ok()
                .and_then(|index| index.checked_mul(4))
                .ok_or_else(|| Error::InvalidArgument("ARM64 relocation instruction offset overflowed".into()))?;
            let source_address = checked_instruction_address(source_start, offset, "source")?;
            let destination_address = checked_instruction_address(destination_start, offset, "destination")?;
            let original_word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let info = analyze_arm64_instruction(source_address, original_word)?;
            let mut relocated_word = original_word;
            let result = unsafe {
                rf_arm64_relocator_relocate_direct(
                    source_address,
                    destination_address,
                    original_word,
                    &mut relocated_word,
                )
            };

            let (status, relocated_word) = match result {
                0 => (
                    if info.pc_relative {
                        Arm64DirectRelocationStatus::Relocated
                    } else {
                        Arm64DirectRelocationStatus::Copied
                    },
                    Some(relocated_word),
                ),
                1 => {
                    complete = false;
                    (Arm64DirectRelocationStatus::OutOfRange, None)
                }
                2 => {
                    return Err(Error::State(
                        "ARM64 relocator reported an internal relocation error".into(),
                    ))
                }
                other => {
                    return Err(Error::State(format!(
                        "ARM64 relocator returned an unknown relocation result {other}"
                    )))
                }
            };

            if let Some(word) = relocated_word {
                output.extend_from_slice(&word.to_le_bytes());
            }
            entries.push(Arm64RelocationEntry {
                source_address,
                destination_address,
                original_word,
                relocated_word,
                info,
                status,
            });
        }

        Ok(Arm64RelocationPlan {
            source_start,
            destination_start,
            entries,
            output: complete.then_some(output),
        })
    }

    #[cfg(not(quickjs_arm64_relocator))]
    {
        Err(Error::Unsupported(
            "ARM64 relocation planning is not compiled for this runtime target".into(),
        ))
    }
}

fn validate_relocation_input(bytes: &[u8], source_start: u64, destination_start: u64) -> Result<()> {
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return Err(Error::InvalidArgument(
            "ARM64 relocation input must contain one or more complete instructions".into(),
        ));
    }
    if bytes.len() / 4 > MAX_ARM64_RELOCATION_INSTRUCTIONS {
        return Err(Error::InvalidArgument(format!(
            "ARM64 relocation input exceeds {MAX_ARM64_RELOCATION_INSTRUCTIONS} instructions"
        )));
    }
    validate_code_address(source_start, "ARM64 relocation source address")?;
    validate_code_address(destination_start, "ARM64 relocation destination address")?;
    let last_offset = u64::try_from(bytes.len() - 4)
        .map_err(|_| Error::InvalidArgument("ARM64 relocation input length is too large".into()))?;
    checked_instruction_address(source_start, last_offset, "source")?;
    checked_instruction_address(destination_start, last_offset, "destination")?;
    Ok(())
}

fn validate_code_address(address: u64, name: &str) -> Result<()> {
    if address % 4 != 0 {
        return Err(Error::InvalidArgument(format!("{name} must be 4-byte aligned")));
    }
    validate_signed_address(address, name)
}

fn validate_signed_address(address: u64, name: &str) -> Result<()> {
    if address > i64::MAX as u64 {
        return Err(Error::InvalidArgument(format!(
            "{name} exceeds the supported signed address range"
        )));
    }
    Ok(())
}

fn checked_instruction_address(start: u64, offset: u64, role: &str) -> Result<u64> {
    let address = start
        .checked_add(offset)
        .ok_or_else(|| Error::InvalidArgument(format!("ARM64 relocation {role} address overflowed")))?;
    validate_code_address(address, &format!("ARM64 relocation {role} address"))?;
    Ok(address)
}

#[cfg(quickjs_arm64_relocator)]
fn relocation_info_from_raw(raw: RawArm64RelocationInfo) -> Arm64RelocationInfo {
    let kind = match raw.kind {
        0 => Arm64RelocationKind::Unknown,
        1 => Arm64RelocationKind::Branch,
        2 => Arm64RelocationKind::BranchLink,
        3 => Arm64RelocationKind::ConditionalBranch,
        4 => Arm64RelocationKind::CompareAndBranchZero,
        5 => Arm64RelocationKind::CompareAndBranchNonZero,
        6 => Arm64RelocationKind::TestBitAndBranchZero,
        7 => Arm64RelocationKind::TestBitAndBranchNonZero,
        8 => Arm64RelocationKind::BranchRegister,
        9 => Arm64RelocationKind::BranchLinkRegister,
        10 => Arm64RelocationKind::Return,
        11 => Arm64RelocationKind::Address,
        12 => Arm64RelocationKind::AddressPage,
        13 => Arm64RelocationKind::LoadLiteral,
        14 => Arm64RelocationKind::LoadSignedWordLiteral,
        15 => Arm64RelocationKind::LoadFloatingLiteral,
        16 => Arm64RelocationKind::PrefetchLiteral,
        17 => Arm64RelocationKind::Other,
        _ => Arm64RelocationKind::Unknown,
    };
    let pc_relative = raw.pc_relative != 0;
    let register = matches!(
        kind,
        Arm64RelocationKind::CompareAndBranchZero
            | Arm64RelocationKind::CompareAndBranchNonZero
            | Arm64RelocationKind::TestBitAndBranchZero
            | Arm64RelocationKind::TestBitAndBranchNonZero
            | Arm64RelocationKind::BranchRegister
            | Arm64RelocationKind::BranchLinkRegister
            | Arm64RelocationKind::Return
    )
    .then_some(raw.register);
    let destination_register = matches!(
        kind,
        Arm64RelocationKind::Address
            | Arm64RelocationKind::AddressPage
            | Arm64RelocationKind::LoadLiteral
            | Arm64RelocationKind::LoadSignedWordLiteral
            | Arm64RelocationKind::LoadFloatingLiteral
    )
    .then_some(raw.destination_register);
    Arm64RelocationInfo {
        kind,
        target: pc_relative.then_some(raw.target),
        pc_relative,
        condition: (kind == Arm64RelocationKind::ConditionalBranch).then_some(raw.condition as u32),
        register,
        bit: matches!(
            kind,
            Arm64RelocationKind::TestBitAndBranchZero | Arm64RelocationKind::TestBitAndBranchNonZero
        )
        .then_some(raw.bit),
        destination_register,
        signed_load: kind == Arm64RelocationKind::LoadSignedWordLiteral && raw.signed_load != 0,
        floating_size: (kind == Arm64RelocationKind::LoadFloatingLiteral).then_some(raw.floating_size as u32),
    }
}

#[cfg(all(test, quickjs_arm64_relocator))]
mod tests {
    use super::*;

    fn one_word(word: u32) -> [u8; 4] {
        word.to_le_bytes()
    }

    #[test]
    fn direct_relocation_preserves_pc_relative_targets() {
        let source = 0x1000_0000;
        let destination = 0x1000_8000;
        let cases = [
            (0x1400_0002, Arm64RelocationKind::Branch),
            (0x9400_0002, Arm64RelocationKind::BranchLink),
            (0x5400_0040, Arm64RelocationKind::ConditionalBranch),
            (0xb400_0040, Arm64RelocationKind::CompareAndBranchZero),
            (0xb500_0041, Arm64RelocationKind::CompareAndBranchNonZero),
            (0x3600_0040, Arm64RelocationKind::TestBitAndBranchZero),
            (0x3700_0041, Arm64RelocationKind::TestBitAndBranchNonZero),
            (0x1000_0040, Arm64RelocationKind::Address),
            (0xb000_0000, Arm64RelocationKind::AddressPage),
            (0x5800_0040, Arm64RelocationKind::LoadLiteral),
            (0x9800_0040, Arm64RelocationKind::LoadSignedWordLiteral),
            (0x1c00_0040, Arm64RelocationKind::LoadFloatingLiteral),
            (0xd800_0040, Arm64RelocationKind::PrefetchLiteral),
        ];

        for (word, expected_kind) in cases {
            let plan = plan_arm64_relocation(&one_word(word), source, destination).expect("plan");
            let entry = &plan.entries[0];
            assert_eq!(entry.info.kind, expected_kind);
            assert_eq!(entry.status, Arm64DirectRelocationStatus::Relocated);
            let relocated = entry.relocated_word.expect("relocated word");
            let relocated_info = analyze_arm64_instruction(destination, relocated).expect("relocated analysis");
            assert_eq!(relocated_info.kind, expected_kind);
            assert_eq!(relocated_info.target, entry.info.target);
            assert!(plan.directly_relocatable());
        }
    }

    #[test]
    fn direct_relocation_copies_non_pc_relative_instructions() {
        let input = one_word(0xd503_201f);
        let plan = plan_arm64_relocation(&input, 0x1000, 0x2000).expect("plan");
        assert_eq!(plan.entries[0].info.kind, Arm64RelocationKind::Other);
        assert_eq!(plan.entries[0].status, Arm64DirectRelocationStatus::Copied);
        assert_eq!(plan.output.as_deref(), Some(input.as_slice()));
    }

    #[test]
    fn direct_relocation_marks_far_pc_relative_targets_for_fallback() {
        let plan = plan_arm64_relocation(&one_word(0x1400_0002), 0x1000, 0x1_0000_0000).expect("plan");
        assert_eq!(plan.entries[0].status, Arm64DirectRelocationStatus::OutOfRange);
        assert_eq!(plan.entries[0].relocated_word, None);
        assert!(plan.output.is_none());
        assert!(plan.requires_fallback());
    }

    #[test]
    fn relocation_rejects_unaligned_oversized_and_wrapping_inputs() {
        assert!(matches!(
            plan_arm64_relocation(&one_word(0xd503_201f), 0x1002, 0x2000),
            Err(Error::InvalidArgument(_))
        ));
        assert!(matches!(
            plan_arm64_relocation(&one_word(0xd503_201f), 0x1000, i64::MAX as u64 + 1),
            Err(Error::InvalidArgument(_))
        ));
        assert!(matches!(
            plan_arm64_relocation(&one_word(0x17ff_ffff), 0, 0x1000),
            Err(Error::InvalidArgument(_))
        ));
        let oversized = vec![0u8; (MAX_ARM64_RELOCATION_INSTRUCTIONS + 1) * 4];
        assert!(matches!(
            plan_arm64_relocation(&oversized, 0x1000, 0x2000),
            Err(Error::InvalidArgument(_))
        ));
    }
}
