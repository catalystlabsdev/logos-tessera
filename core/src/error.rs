//! Refusal codes (U.7). Codes are stable: never renumber, only append.

/// Why a configuration is invalid. Carried by [`Error::InvalidConfig`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigFault {
    /// The member list is empty.
    NoMembers,
    /// More than [`crate::MAX_MEMBERS`] members.
    TooManyMembers,
    /// Threshold is zero.
    ZeroThreshold,
    /// Threshold exceeds the total weight of members holding APPROVE.
    ThresholdUnreachable,
    /// A member has weight zero.
    ZeroWeight,
    /// Two members share a key.
    DuplicateMember,
    /// A member key is not a valid BIP-340 x-only public key.
    InvalidMemberKey,
    /// A member has no roles, or role bits outside PROPOSE|APPROVE|EXECUTE.
    InvalidRoles,
    /// No member holds PROPOSE, so nothing could ever be proposed.
    NoProposer,
    /// No member holds EXECUTE, so nothing could ever be executed.
    NoExecutor,
    /// The epoch counter would overflow.
    EpochOverflow,
}

impl ConfigFault {
    /// Stable sub-code, unique within [`Error::InvalidConfig`].
    pub const fn code(&self) -> u32 {
        match self {
            ConfigFault::NoMembers => 1,
            ConfigFault::TooManyMembers => 2,
            ConfigFault::ZeroThreshold => 3,
            ConfigFault::ThresholdUnreachable => 4,
            ConfigFault::ZeroWeight => 5,
            ConfigFault::DuplicateMember => 6,
            ConfigFault::InvalidMemberKey => 7,
            ConfigFault::InvalidRoles => 8,
            ConfigFault::NoProposer => 9,
            ConfigFault::NoExecutor => 10,
            ConfigFault::EpochOverflow => 11,
        }
    }

    /// One-line operator action.
    pub const fn message(&self) -> &'static str {
        match self {
            ConfigFault::NoMembers => "invalid config: add at least one member",
            ConfigFault::TooManyMembers => "invalid config: reduce the member list to the supported maximum",
            ConfigFault::ZeroThreshold => "invalid config: set a threshold of at least 1",
            ConfigFault::ThresholdUnreachable => {
                "invalid config: lower the threshold or add approve weight so it is reachable"
            }
            ConfigFault::ZeroWeight => "invalid config: give every member a weight of at least 1",
            ConfigFault::DuplicateMember => "invalid config: remove the duplicated member key",
            ConfigFault::InvalidMemberKey => "invalid config: replace the member key that is not a valid BIP-340 key",
            ConfigFault::InvalidRoles => "invalid config: give every member only PROPOSE/APPROVE/EXECUTE role bits, at least one",
            ConfigFault::NoProposer => "invalid config: give at least one member the propose role",
            ConfigFault::NoExecutor => "invalid config: give at least one member the execute role",
            ConfigFault::EpochOverflow => "invalid config: epoch exhausted; migrate to a new multisig",
        }
    }
}

/// Every refusal the rules can return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NotInitialised,
    AlreadyInitialised,
    StaleEpoch,
    NotProposer,
    NotApprover,
    NotExecutor,
    DuplicateApprover,
    UnknownKey,
    BadSignature,
    BelowThreshold,
    QuorumNoLongerHeld,
    Expired,
    TimelockActive,
    WindowInvalid,
    WindowTooWide,
    NotQueued,
    AlreadyExecuted,
    Cancelled,
    CallNotAllowed,
    ForbiddenAccount,
    InvalidConfig(ConfigFault),
    DigestMismatch,
    StaleConfigChange,
    Encoding,
}

impl Error {
    /// All variants with a representative payload, for tables and tests.
    pub const ALL: &'static [Error] = &[
        Error::NotInitialised,
        Error::AlreadyInitialised,
        Error::StaleEpoch,
        Error::NotProposer,
        Error::NotApprover,
        Error::NotExecutor,
        Error::DuplicateApprover,
        Error::UnknownKey,
        Error::BadSignature,
        Error::BelowThreshold,
        Error::QuorumNoLongerHeld,
        Error::Expired,
        Error::TimelockActive,
        Error::WindowInvalid,
        Error::WindowTooWide,
        Error::NotQueued,
        Error::AlreadyExecuted,
        Error::Cancelled,
        Error::CallNotAllowed,
        Error::ForbiddenAccount,
        Error::InvalidConfig(ConfigFault::NoMembers),
        Error::DigestMismatch,
        Error::StaleConfigChange,
        Error::Encoding,
    ];

    /// Stable numeric code. `InvalidConfig` shares one code; see [`ConfigFault::code`].
    pub const fn code(&self) -> u32 {
        match self {
            Error::NotInitialised => 1,
            Error::AlreadyInitialised => 2,
            Error::StaleEpoch => 3,
            Error::NotProposer => 4,
            Error::NotApprover => 5,
            Error::NotExecutor => 6,
            Error::DuplicateApprover => 7,
            Error::UnknownKey => 8,
            Error::BadSignature => 9,
            Error::BelowThreshold => 10,
            Error::QuorumNoLongerHeld => 11,
            Error::Expired => 12,
            Error::TimelockActive => 13,
            Error::WindowInvalid => 14,
            Error::WindowTooWide => 15,
            Error::NotQueued => 16,
            Error::AlreadyExecuted => 17,
            Error::Cancelled => 18,
            Error::CallNotAllowed => 19,
            Error::ForbiddenAccount => 20,
            Error::InvalidConfig(_) => 21,
            Error::DigestMismatch => 22,
            Error::StaleConfigChange => 23,
            Error::Encoding => 24,
        }
    }

    /// Stable name of the variant.
    pub const fn name(&self) -> &'static str {
        match self {
            Error::NotInitialised => "NotInitialised",
            Error::AlreadyInitialised => "AlreadyInitialised",
            Error::StaleEpoch => "StaleEpoch",
            Error::NotProposer => "NotProposer",
            Error::NotApprover => "NotApprover",
            Error::NotExecutor => "NotExecutor",
            Error::DuplicateApprover => "DuplicateApprover",
            Error::UnknownKey => "UnknownKey",
            Error::BadSignature => "BadSignature",
            Error::BelowThreshold => "BelowThreshold",
            Error::QuorumNoLongerHeld => "QuorumNoLongerHeld",
            Error::Expired => "Expired",
            Error::TimelockActive => "TimelockActive",
            Error::WindowInvalid => "WindowInvalid",
            Error::WindowTooWide => "WindowTooWide",
            Error::NotQueued => "NotQueued",
            Error::AlreadyExecuted => "AlreadyExecuted",
            Error::Cancelled => "Cancelled",
            Error::CallNotAllowed => "CallNotAllowed",
            Error::ForbiddenAccount => "ForbiddenAccount",
            Error::InvalidConfig(_) => "InvalidConfig",
            Error::DigestMismatch => "DigestMismatch",
            Error::StaleConfigChange => "StaleConfigChange",
            Error::Encoding => "Encoding",
        }
    }

    /// One-line operator action.
    pub const fn message(&self) -> &'static str {
        match self {
            Error::NotInitialised => "multisig not activated: collect threshold activation approvals and submit Activate",
            Error::AlreadyInitialised => "multisig already activated: nothing to do",
            Error::StaleEpoch => "configuration changed since signing: re-sign the proposal under the current epoch",
            Error::NotProposer => "proposer lacks the propose role: have a member with propose sign the proposal",
            Error::NotApprover => "an approval is from a key without the approve role: drop it and collect another",
            Error::NotExecutor => "executor lacks the execute role: submit with a member holding execute",
            Error::DuplicateApprover => "the same key approved twice: drop the duplicate approval",
            Error::UnknownKey => "a signature is from a key that is not a current member: drop it",
            Error::BadSignature => "a signature does not verify for this action and purpose: re-collect it",
            Error::BelowThreshold => "approval weight below threshold: collect more approvals",
            Error::QuorumNoLongerHeld => {
                "approvers no longer reach the current threshold: re-propose and re-approve"
            }
            Error::Expired => "proposal expires before the transaction window closes: re-propose with a later expiry",
            Error::TimelockActive => "time lock not elapsed for this window: resubmit with a later window",
            Error::WindowInvalid => "transaction window is empty: rebuild with start before end",
            Error::WindowTooWide => "transaction window exceeds the maximum: rebuild with a narrower window",
            Error::NotQueued => "no matching queued action: queue the action first or check the digest",
            Error::AlreadyExecuted => "action already executed: nothing to do",
            Error::Cancelled => "action was cancelled: re-propose if still wanted",
            Error::CallNotAllowed => "a call is outside the allowed action set: change the action or the action set",
            Error::ForbiddenAccount => {
                "a call names Tessera itself or a root-authorised account: remove that account from the action"
            }
            Error::InvalidConfig(f) => f.message(),
            Error::DigestMismatch => "action does not match the queued digest: submit the exact queued proposal",
            Error::StaleConfigChange => {
                "another configuration change applied first: re-propose this change under the current epoch"
            }
            Error::Encoding => "encoding failed: report this as a bug",
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} ({}): {}", self.name(), self.code(), self.message())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;
