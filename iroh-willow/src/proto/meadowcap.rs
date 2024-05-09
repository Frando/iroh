use serde::{Deserialize, Serialize};

use crate::util::Encoder;

use super::{
    grouping::Area,
    keys::{self, NamespaceSecretKey, UserSecretKey, PUBLIC_KEY_LENGTH},
    willow::{AuthorisedEntry, Entry, Unauthorised},
};

pub type UserSignature = keys::UserSignature;
pub type UserPublicKey = keys::UserPublicKey;
pub type NamespacePublicKey = keys::NamespacePublicKey;
pub type NamespaceSignature = keys::NamespaceSignature;

pub fn is_authorised_write(entry: &Entry, token: &MeadowcapAuthorisationToken) -> bool {
    let (capability, signature) = token.as_parts();

    capability.is_valid()
        && capability.access_mode() == AccessMode::Write
        && capability.granted_area().includes_entry(entry)
        && capability
            .receiver()
            // TODO: This allocates each time, avoid
            .verify(&entry.encode().expect("encoding not to fail"), signature)
            .is_ok()
}

pub fn create_token(
    entry: &Entry,
    capability: McCapability,
    secret_key: &UserSecretKey,
) -> MeadowcapAuthorisationToken {
    // TODO: This allocates each time, avoid
    let signable = entry.encode().expect("encoding not to fail");
    let signature = secret_key.sign(&signable);
    MeadowcapAuthorisationToken::from_parts(capability, signature)
}

pub fn attach_authorisation(
    entry: Entry,
    capability: McCapability,
    secret_key: &UserSecretKey,
) -> Result<AuthorisedEntry, InvalidParams> {
    if capability.access_mode() != AccessMode::Write
        || !capability.granted_area().includes_entry(&entry)
        || capability.receiver() != &secret_key.public_key()
    {
        return Err(InvalidParams);
    }
    let token = create_token(&entry, capability, secret_key);
    Ok(AuthorisedEntry::from_parts_unchecked(entry, token))
}

#[derive(Debug, thiserror::Error)]
#[error("invalid parameters")]
pub struct InvalidParams;

#[derive(Debug, thiserror::Error)]
#[error("invalid capability")]
pub struct InvalidCapability;

/// To be used as an AuthorisationToken for Willow.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct MeadowcapAuthorisationToken {
    /// Certifies that an Entry may be written.
    pub capability: McCapability,
    /// Proves that the Entry was created by the receiver of the capability.
    pub signature: UserSignature,
}

// TODO: We clone these a bunch where it wouldn't be needed if we could create a reference type to
// which the [`MeadowcapAuthorisationToken`] would deref to, but I couldn't make it work nice
// enough.
// #[derive(Debug, Clone, Eq, PartialEq)]
// pub struct MeadowcapAuthorisationTokenRef<'a> {
//     /// Certifies that an Entry may be written.
//     pub capability: &'a McCapability,
//     /// Proves that the Entry was created by the receiver of the capability.
//     pub signature: &'a UserSignature,
// }

impl MeadowcapAuthorisationToken {
    pub fn from_parts(capability: McCapability, signature: UserSignature) -> Self {
        Self {
            capability,
            signature,
        }
    }
    pub fn as_parts(&self) -> (&McCapability, &UserSignature) {
        (&self.capability, &self.signature)
    }

    pub fn into_parts(self) -> (McCapability, UserSignature) {
        (self.capability, self.signature)
    }
}

impl From<(McCapability, UserSignature)> for MeadowcapAuthorisationToken {
    fn from((capability, signature): (McCapability, UserSignature)) -> Self {
        Self::from_parts(capability, signature)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash, derive_more::From)]
pub enum McCapability {
    Communal(CommunalCapability),
    Owned(OwnedCapability),
}

impl McCapability {
    pub fn access_mode(&self) -> AccessMode {
        match self {
            Self::Communal(cap) => cap.access_mode,
            Self::Owned(cap) => cap.access_mode,
        }
    }
    pub fn receiver(&self) -> &UserPublicKey {
        match self {
            Self::Communal(cap) => cap.receiver(),
            Self::Owned(cap) => cap.receiver(),
        }
    }

    pub fn granted_namespace(&self) -> &NamespacePublicKey {
        match self {
            Self::Communal(cap) => cap.granted_namespace(),
            Self::Owned(cap) => cap.granted_namespace(),
        }
    }

    pub fn granted_area(&self) -> Area {
        match self {
            Self::Communal(cap) => cap.granted_area(),
            Self::Owned(cap) => cap.granted_area(),
        }
    }

    pub fn try_granted_area(&self, area: &Area) -> Result<(), Unauthorised> {
        if !self.granted_area().includes_area(area) {
            Err(Unauthorised)
        } else {
            Ok(())
        }
    }

    pub fn is_valid(&self) -> bool {
        match self {
            Self::Communal(cap) => cap.is_valid(),
            Self::Owned(cap) => cap.is_valid(),
        }
    }
    pub fn validate(&self) -> Result<(), InvalidCapability> {
        match self.is_valid() {
            true => Ok(()),
            false => Err(InvalidCapability),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Hash)]
pub enum AccessMode {
    Read,
    Write,
}

/// A capability that authorizes reads or writes in communal namespaces.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct CommunalCapability {
    /// The kind of access this grants.
    access_mode: AccessMode,
    /// The namespace in which this grants access.
    namespace_key: NamespacePublicKey,
    /// The subspace for which and to whom this grants access.
    ///
    /// Remember that we assume SubspaceId and UserPublicKey to be the same types.
    user_key: UserPublicKey,
    /// Successive authorisations of new UserPublicKeys, each restricted to a particular Area.
    delegations: Vec<(Area, UserPublicKey, UserSignature)>,
}

impl CommunalCapability {
    pub fn receiver(&self) -> &UserPublicKey {
        // TODO: support delegations
        &self.user_key
    }

    pub fn granted_namespace(&self) -> &NamespacePublicKey {
        &self.namespace_key
    }

    pub fn granted_area(&self) -> Area {
        // TODO: support delegations
        Area::subspace(self.user_key.into())
    }

    pub fn is_valid(&self) -> bool {
        if self.delegations.is_empty() {
            // communal capabilities without delegations are always valid
            true
        } else {
            // TODO: support delegations
            false
        }
    }
}

/// A capability that authorizes reads or writes in owned namespaces.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct OwnedCapability {
    /// The kind of access this grants.
    access_mode: AccessMode,
    /// The namespace for which this grants access.
    namespace_key: NamespacePublicKey,
    /// The user to whom this grants access; granting access for the full namespace_key, not just to a subspace.
    user_key: UserPublicKey,
    /// Authorisation of the user_key by the namespace_key.,
    initial_authorisation: NamespaceSignature,
    /// Successive authorisations of new UserPublicKeys, each restricted to a particular Area.
    delegations: Vec<(Area, UserPublicKey, UserSignature)>,
}

impl OwnedCapability {
    pub fn new(
        namespace_secret_key: &NamespaceSecretKey,
        user_key: UserPublicKey,
        access_mode: AccessMode,
    ) -> Self {
        let namespace_key = namespace_secret_key.public_key();
        let signable = Self::signable(access_mode, &user_key);
        let initial_authorisation = namespace_secret_key.sign(&signable);
        Self {
            access_mode,
            namespace_key,
            user_key,
            initial_authorisation,
            delegations: Default::default(),
        }
    }

    pub fn receiver(&self) -> &UserPublicKey {
        // TODO: support delegations
        &self.user_key
    }

    pub fn granted_namespace(&self) -> &NamespacePublicKey {
        &self.namespace_key
    }

    pub fn granted_area(&self) -> Area {
        // TODO: support delegations
        Area::full()
    }

    pub fn is_valid(&self) -> bool {
        if self.delegations.is_empty() {
            let signable = Self::signable(self.access_mode, &self.user_key);
            self.namespace_key
                .verify(&signable, &self.initial_authorisation)
                .is_ok()
        } else {
            // TODO: support delegations
            false
        }
    }

    fn signable(access_mode: AccessMode, user_key: &UserPublicKey) -> [u8; PUBLIC_KEY_LENGTH + 1] {
        let mut signable = [0u8; PUBLIC_KEY_LENGTH + 1];
        // https://willowprotocol.org/specs/meadowcap/index.html#owned_cap_valid
        // An OwnedCapability with zero delegations is valid if initial_authorisation
        // is a NamespaceSignature issued by the namespace_key over
        // either the byte 0x02 (if access_mode is read)
        // or the byte 0x03 (if access_mode is write),
        // followed by the user_key (encoded via encode_user_pk).
        signable[0] = match access_mode {
            AccessMode::Read => 0x02,
            AccessMode::Write => 0x03,
        };
        signable[1..].copy_from_slice(user_key.as_bytes());
        signable
    }
}
