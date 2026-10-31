//! The `ssh-agent` presence method. The agent issues single-use challenges bound to a peer and a request, and
//! verifies their SSHSIG signatures against registered keys; the client relays them to the SSH agent at
//! `$SSH_AUTH_SOCK`.

pub const METHOD: &str = "ssh-agent";
/// SSHSIG namespace, so that a signature made for another purpose never counts as an approval.
pub const NAMESPACE: &str = "co.0w0.mairu.authorize";

pub const ACTION_ASSUME_ROLE: &str = "assume-role";
pub const ACTION_USE_CREDENTIALS: &str = "use-credentials";
pub const ACTION_APPROVE_POLICY: &str = "approve-policy";
pub const ACTION_UNMARK_TOOLS: &str = "unmark-tools";

pub const DECLINED_NO_SSH_AGENT: &str = "no-ssh-agent";
pub const DECLINED_NO_REGISTERED_KEY: &str = "no-registered-key";
pub const DECLINED_SIGN_FAILED: &str = "sign-failed";

pub const CHALLENGE_LIFETIME: std::time::Duration = std::time::Duration::from_secs(60);
const MAX_CHALLENGES_PER_PEER: usize = 4;

/// The `authorized_keys` option for requiring user verification, as approval anchors record it.
const VERIFY_REQUIRED: &str = "verify-required";

const SK_FLAG_USER_PRESENT: u8 = 0x01;
const SK_FLAG_USER_VERIFIED: u8 = 0x04;
/// `flags (u8) || counter (u32)` after the inner signature of `sk-` keys.
const SK_TRAILER_SIZE: usize = 5;

/// A public key registered in `ssh_agent_keys`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredKey {
    pub public: ssh_key::PublicKey,
    pub require_user_verification: bool,
}

impl RegisteredKey {
    /// An OpenSSH public key line. `require_user_verification` is valid for `sk-` keys only.
    pub fn parse(line: &str, require_user_verification: bool) -> Result<Self, String> {
        let public = ssh_key::PublicKey::from_openssh(line.trim()).map_err(|e| e.to_string())?;
        let key = Self {
            public,
            require_user_verification,
        };
        match key.public.algorithm() {
            ssh_key::Algorithm::Ed25519
            | ssh_key::Algorithm::Ecdsa { .. }
            | ssh_key::Algorithm::Rsa { .. }
            | ssh_key::Algorithm::SkEd25519
            | ssh_key::Algorithm::SkEcdsaSha2NistP256 => {}
            other => return Err(format!("unsupported key type {}", other.as_str())),
        }
        if require_user_verification && !key.is_sk() {
            return Err("require_user_verification applies to sk- keys only".to_owned());
        }
        Ok(key)
    }

    /// A key line as an approval anchor records it: `[verify-required ]<type> <base64> <comment>`.
    pub fn from_anchor_line(line: &str) -> Result<Self, String> {
        match line.trim().strip_prefix(VERIFY_REQUIRED) {
            Some(rest) if rest.starts_with(' ') => Self::parse(rest, true),
            _ => Self::parse(line, false),
        }
    }

    pub fn to_anchor_line(&self) -> String {
        let line = self.public.to_openssh().unwrap_or_default();
        if self.require_user_verification {
            format!("{VERIFY_REQUIRED} {line}")
        } else {
            line
        }
    }

    /// The key line without options.
    pub fn to_openssh(&self) -> String {
        self.public.to_openssh().unwrap_or_default()
    }

    /// `SHA256:...`, as `ssh-add -l` prints it.
    pub fn fingerprint(&self) -> String {
        self.public
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string()
    }

    pub fn is_sk(&self) -> bool {
        matches!(
            self.public.algorithm(),
            ssh_key::Algorithm::SkEd25519 | ssh_key::Algorithm::SkEcdsaSha2NistP256
        )
    }

    /// Verifies an SSHSIG over `message`, and for `sk-` keys the flags the signature carries.
    pub fn verify(&self, message: &[u8], sig: &ssh_key::SshSig) -> Result<(), String> {
        self.public
            .verify(NAMESPACE, message, sig)
            .map_err(|e| format!("the signature does not verify: {e}"))?;
        if self.is_sk() {
            let flags = sk_flags(sig).ok_or("the signature has no sk- flags")?;
            if flags & SK_FLAG_USER_PRESENT == 0 {
                return Err("the security key did not assert user presence".to_owned());
            }
            if self.require_user_verification && flags & SK_FLAG_USER_VERIFIED == 0 {
                return Err("the security key did not assert user verification".to_owned());
            }
        }
        Ok(())
    }
}

/// `ssh-key` checks the sk- signature but not its flags byte, which leads the trailer it keeps after the signature.
fn sk_flags(sig: &ssh_key::SshSig) -> Option<u8> {
    let bytes = sig.signature().as_bytes();
    let at = bytes.len().checked_sub(SK_TRAILER_SIZE)?;
    bytes.get(at).copied()
}

/// What a challenge binds to: the requesting process and the exact request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub pid: u32,
    pub start_time: u64,
    pub action: &'static str,
    pub server_id: String,
    pub rolespec: Option<crate::proto::Rolespec>,
    pub request_digest: [u8; 32],
}

/// An outstanding challenge, holding `G` until it is answered, expires or is dropped.
#[derive(Debug)]
pub struct PendingChallenge<G> {
    statement: Vec<u8>,
    binding: Binding,
    expires: std::time::Duration,
    pub guard: Option<G>,
}

impl<G> PendingChallenge<G> {
    pub fn is_for(&self, pid: u32, start_time: u64) -> bool {
        self.binding.pid == pid && self.binding.start_time == start_time
    }

    pub fn action(&self) -> &'static str {
        self.binding.action
    }

    /// Checks the challenge against the retried request and the signature against `keys`. Returns the key that
    /// signed.
    pub fn verify<'k>(
        &self,
        binding: &Binding,
        now: std::time::Duration,
        sshsig: &[u8],
        keys: &'k [RegisteredKey],
    ) -> Result<&'k RegisteredKey, String> {
        use ssh_encoding::{Decode, Reader};
        if now >= self.expires {
            return Err("the challenge expired".to_owned());
        }
        if !self.is_for(binding.pid, binding.start_time) {
            return Err("the challenge was issued to another process".to_owned());
        }
        if self.binding.action != binding.action
            || self.binding.request_digest != binding.request_digest
        {
            return Err("the challenge was issued for another request".to_owned());
        }
        let mut reader = sshsig;
        let sig = ssh_key::SshSig::decode(&mut reader)
            .map_err(|e| format!("the signature is not a valid SSHSIG: {e}"))?;
        if !reader.is_finished() {
            return Err("the signature has trailing data".to_owned());
        }
        if sig.namespace() != NAMESPACE {
            return Err(format!(
                "the signature is for namespace {:?}, not {NAMESPACE:?}",
                sig.namespace()
            ));
        }
        let key = keys
            .iter()
            .find(|k| k.public.key_data() == sig.public_key())
            .ok_or("the signature is not by a registered key")?;
        key.verify(&self.statement, &sig)?;
        Ok(key)
    }
}

/// Outstanding challenges. Removing one is what makes it single use.
#[derive(Debug)]
pub struct Challenges<G> {
    instance_id: [u8; 16],
    pending: std::collections::HashMap<[u8; 16], PendingChallenge<G>>,
}

impl<G> Challenges<G> {
    /// `instance_id` is chosen once per agent, so that a statement of a previous agent never matches.
    pub fn new(instance_id: [u8; 16]) -> Self {
        Self {
            instance_id,
            pending: Default::default(),
        }
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Issues a challenge for `binding` that `keys` may answer. Keeps at most a few per peer, evicting the oldest.
    /// Returns the challenge and what was evicted, for the caller to drop outside any lock.
    pub fn issue(
        &mut self,
        binding: Binding,
        keys: &[RegisteredKey],
        now: std::time::Duration,
        guard: Option<G>,
    ) -> (
        crate::proto::AuthorizationChallenge,
        Vec<PendingChallenge<G>>,
    ) {
        use prost::Message;
        let mut evicted = self.sweep(now);
        let mut mine: Vec<([u8; 16], std::time::Duration)> = self
            .pending
            .iter()
            .filter(|(_, c)| c.is_for(binding.pid, binding.start_time))
            .map(|(id, c)| (*id, c.expires))
            .collect();
        mine.sort_by_key(|(_, expires)| *expires);
        while mine.len() >= MAX_CHALLENGES_PER_PEER {
            let (id, _) = mine.remove(0);
            evicted.extend(self.pending.remove(&id));
        }

        let expires_at =
            prost_types::Timestamp::from(std::time::SystemTime::now() + CHALLENGE_LIFETIME);
        let statement = crate::proto::AuthorizationStatement {
            nonce: rand::random::<[u8; 32]>().to_vec(),
            agent_instance_id: self.instance_id.to_vec(),
            peer_pid: binding.pid,
            peer_start_time: binding.start_time,
            action: binding.action.to_owned(),
            server_id: binding.server_id.clone(),
            rolespec: binding.rolespec.clone(),
            request_digest: binding.request_digest.to_vec(),
            expires_at: Some(expires_at),
        }
        .encode_to_vec();
        let challenge_id = loop {
            let id = rand::random::<[u8; 16]>();
            if !self.pending.contains_key(&id) {
                break id;
            }
        };
        let challenge = crate::proto::AuthorizationChallenge {
            challenge_id: challenge_id.to_vec(),
            statement: statement.clone(),
            key_fingerprints: keys.iter().map(RegisteredKey::fingerprint).collect(),
            expires_at: Some(expires_at),
            method: METHOD.to_owned(),
        };
        self.pending.insert(
            challenge_id,
            PendingChallenge {
                statement,
                binding,
                expires: now + CHALLENGE_LIFETIME,
                guard,
            },
        );
        (challenge, evicted)
    }

    /// Removes the challenge, whatever happens next.
    pub fn take(&mut self, challenge_id: &[u8]) -> Option<PendingChallenge<G>> {
        let id: [u8; 16] = challenge_id.try_into().ok()?;
        self.pending.remove(&id)
    }

    /// Removes the challenge when it was issued to the process `(pid, start_time)`; another process cannot use or
    /// withdraw it.
    pub fn take_for(
        &mut self,
        challenge_id: &[u8],
        pid: u32,
        start_time: u64,
    ) -> Option<PendingChallenge<G>> {
        let id: [u8; 16] = challenge_id.try_into().ok()?;
        if !self.pending.get(&id)?.is_for(pid, start_time) {
            return None;
        }
        self.pending.remove(&id)
    }

    /// Removes expired challenges and returns them.
    pub fn sweep(&mut self, now: std::time::Duration) -> Vec<PendingChallenge<G>> {
        let expired: Vec<[u8; 16]> = self
            .pending
            .iter()
            .filter(|(_, c)| now >= c.expires)
            .map(|(id, _)| *id)
            .collect();
        expired
            .iter()
            .filter_map(|id| self.pending.remove(id))
            .collect()
    }

    /// Removes every challenge and returns them.
    pub fn clear(&mut self) -> Vec<PendingChallenge<G>> {
        self.pending.drain().map(|(_, c)| c).collect()
    }
}

/// Sets the response a retried request carries.
pub fn set_response(
    context: &mut Option<crate::proto::ClientContext>,
    response: Option<crate::proto::AuthorizationResponse>,
) {
    if let Some(response) = response {
        context
            .get_or_insert_with(Default::default)
            .authorization_response = Some(response);
    }
}

/// Whether a request carries a signature, so that the agent will not be asking anyone else.
pub fn is_signed(response: Option<&crate::proto::AuthorizationResponse>) -> bool {
    matches!(
        response.and_then(|r| r.result.as_ref()),
        Some(crate::proto::authorization_response::Result::Sshsig(_))
    )
}

/// The client's side: answers challenges through the SSH agent at `$SSH_AUTH_SOCK`. A decline sticks for the rest
/// of the command, so that a refused or unreachable SSH agent is not asked again after falling back.
#[derive(Debug)]
pub struct Relay {
    socket: Option<std::path::PathBuf>,
    declined: parking_lot::Mutex<Option<&'static str>>,
}

/// At most this many challenges are answered for one RPC; each gate may ask once.
const MAX_ROUNDS: usize = 3;
const AGENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl Relay {
    pub fn from_env() -> std::sync::Arc<Self> {
        Self::new(
            std::env::var_os("SSH_AUTH_SOCK")
                .filter(|s| !s.is_empty())
                .map(std::path::PathBuf::from),
        )
    }

    pub fn new(socket: Option<std::path::PathBuf>) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            socket,
            declined: Default::default(),
        })
    }

    /// Runs `rpc` with the response to each challenge it is refused with, until it is not refused with one.
    /// `notice` gives the lines to print before asking the SSH agent, from the refusal and the key's comment; empty
    /// prints nothing.
    pub async fn with_challenges<T, N, F, Fut>(&self, notice: N, mut rpc: F) -> tonic::Result<T>
    where
        N: Fn(&crate::proto::AuthorizationError, &str) -> String,
        F: FnMut(Option<crate::proto::AuthorizationResponse>) -> Fut,
        Fut: std::future::Future<Output = tonic::Result<T>>,
    {
        let mut response = None;
        let mut rounds = 0;
        loop {
            let result = rpc(response.take()).await;
            let refusal = match &result {
                Err(status) => crate::proto::AuthorizationError::from_status(status),
                Ok(_) => None,
            };
            let (refusal, challenge) = match refusal {
                Some(mut r)
                    if r.reason() == crate::proto::authorization_error::Reason::Challenge
                        && rounds < MAX_ROUNDS =>
                {
                    match r.challenge.take() {
                        Some(c) => (r, c),
                        None => return result,
                    }
                }
                _ => return result,
            };
            rounds += 1;
            response = Some(
                self.respond(&challenge, |comment| notice(&refusal, comment))
                    .await,
            );
        }
    }

    /// Signs the challenge's statement with the first registered key the SSH agent holds, or declines.
    pub async fn respond(
        &self,
        challenge: &crate::proto::AuthorizationChallenge,
        notice: impl FnOnce(&str) -> String,
    ) -> crate::proto::AuthorizationResponse {
        use crate::proto::authorization_response::Result as R;
        let result = match self.sign(challenge, notice).await {
            Ok(sshsig) => R::Sshsig(sshsig),
            Err(declined) => {
                *self.declined.lock() = Some(declined);
                R::Declined(declined.to_owned())
            }
        };
        crate::proto::AuthorizationResponse {
            challenge_id: challenge.challenge_id.clone(),
            result: Some(result),
        }
    }

    async fn sign(
        &self,
        challenge: &crate::proto::AuthorizationChallenge,
        notice: impl FnOnce(&str) -> String,
    ) -> Result<Vec<u8>, &'static str> {
        if let Some(declined) = *self.declined.lock() {
            return Err(declined);
        }
        if challenge.method != METHOD {
            return Err(DECLINED_NO_REGISTERED_KEY);
        }
        let Some(socket) = &self.socket else {
            tracing::debug!("SSH_AUTH_SOCK is not set; declining the challenge");
            return Err(DECLINED_NO_SSH_AGENT);
        };
        let mut agent = match SshAgentClient::connect(socket).await {
            Ok(agent) => agent,
            Err(e) => {
                tracing::info!(socket = %socket.display(), err = %e, "SSH agent unreachable; declining the challenge");
                return Err(DECLINED_NO_SSH_AGENT);
            }
        };
        let identities = match agent.identities().await {
            Ok(ids) => ids,
            Err(e) => {
                tracing::info!(socket = %socket.display(), err = %e, "SSH agent failed to list keys; declining the challenge");
                return Err(DECLINED_NO_SSH_AGENT);
            }
        };
        let Some(identity) = identities
            .into_iter()
            .find(|id| challenge.key_fingerprints.contains(&id.fingerprint()))
        else {
            tracing::info!("The SSH agent holds no registered key; declining the challenge");
            return Err(DECLINED_NO_REGISTERED_KEY);
        };
        let notice = notice(&identity.comment);
        if !notice.is_empty() {
            crate::terminal::send(&notice).await;
        }
        let signed_data =
            ssh_key::SshSig::signed_data(NAMESPACE, ssh_key::HashAlg::Sha512, &challenge.statement)
                .map_err(|_| DECLINED_SIGN_FAILED)?;
        let signature = match agent.sign(&identity, &signed_data).await {
            Ok(signature) => signature,
            Err(e) => {
                tracing::info!(err = %e, "The SSH agent did not sign; declining the challenge");
                return Err(DECLINED_SIGN_FAILED);
            }
        };
        sshsig_blob(&identity.key_blob, ssh_key::HashAlg::Sha512, &signature)
            .map_err(|_| DECLINED_SIGN_FAILED)
    }
}

/// A binary SSHSIG around a signature blob exactly as the SSH agent returned it.
pub fn sshsig_blob(
    key_blob: &[u8],
    hash_alg: ssh_key::HashAlg,
    signature_blob: &[u8],
) -> Result<Vec<u8>, ssh_encoding::Error> {
    use ssh_encoding::Encode;
    let mut out = b"SSHSIG".to_vec();
    1u32.encode(&mut out)?;
    key_blob.encode(&mut out)?;
    NAMESPACE.encode(&mut out)?;
    b"".as_slice().encode(&mut out)?;
    hash_alg.as_str().encode(&mut out)?;
    signature_blob.encode(&mut out)?;
    Ok(out)
}

/// A key the SSH agent holds.
#[derive(Debug, Clone)]
pub struct Identity {
    pub key_blob: Vec<u8>,
    pub comment: String,
}

impl Identity {
    /// `SHA256:...`, empty when the blob is no key `ssh-key` knows.
    pub fn fingerprint(&self) -> String {
        use ssh_encoding::Decode;
        ssh_key::public::KeyData::decode(&mut self.key_blob.as_slice())
            .map(|k| k.fingerprint(ssh_key::HashAlg::Sha256).to_string())
            .unwrap_or_default()
    }

    fn is_rsa(&self) -> bool {
        use ssh_encoding::Decode;
        let mut reader = self.key_blob.as_slice();
        String::decode(&mut reader).is_ok_and(|alg| alg == "ssh-rsa")
    }
}

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;
const MAX_MESSAGE_SIZE: usize = 256 * 1024;

/// The two requests of the SSH agent protocol (draft-miller-ssh-agent) that the relay needs.
#[derive(Debug)]
pub struct SshAgentClient {
    stream: tokio::net::UnixStream,
}

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("timed out")]
    Timeout,
    #[error("the SSH agent refused")]
    Failure,
    #[error("malformed answer: {0}")]
    Malformed(String),
}

impl From<ssh_encoding::Error> for AgentError {
    fn from(e: ssh_encoding::Error) -> Self {
        AgentError::Malformed(e.to_string())
    }
}

impl SshAgentClient {
    pub async fn connect(path: &std::path::Path) -> Result<Self, AgentError> {
        let stream = tokio::time::timeout(AGENT_TIMEOUT, tokio::net::UnixStream::connect(path))
            .await
            .map_err(|_| AgentError::Timeout)??;
        Ok(Self { stream })
    }

    pub async fn identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        use ssh_encoding::{Decode, Reader};
        let answer = tokio::time::timeout(
            AGENT_TIMEOUT,
            self.request(&[SSH_AGENTC_REQUEST_IDENTITIES]),
        )
        .await
        .map_err(|_| AgentError::Timeout)??;
        let mut reader = expect(&answer, SSH_AGENT_IDENTITIES_ANSWER)?;
        let count = u32::decode(&mut reader)?;
        let mut identities = vec![];
        for _ in 0..count {
            let key_blob = Vec::<u8>::decode(&mut reader)?;
            let comment = Vec::<u8>::decode(&mut reader)?;
            identities.push(Identity {
                key_blob,
                comment: String::from_utf8_lossy(&comment).into_owned(),
            });
        }
        if !reader.is_finished() {
            return Err(AgentError::Malformed("trailing data".to_owned()));
        }
        Ok(identities)
    }

    /// The signature blob, as the agent encodes it. Waits for whatever the agent's lock takes, up to the
    /// challenge's lifetime.
    pub async fn sign(&mut self, identity: &Identity, data: &[u8]) -> Result<Vec<u8>, AgentError> {
        use ssh_encoding::{Decode, Encode, Reader};
        let flags = if identity.is_rsa() {
            SSH_AGENT_RSA_SHA2_512
        } else {
            0
        };
        let mut message = vec![SSH_AGENTC_SIGN_REQUEST];
        identity.key_blob.encode(&mut message)?;
        data.encode(&mut message)?;
        flags.encode(&mut message)?;
        let answer = tokio::time::timeout(CHALLENGE_LIFETIME, self.request(&message))
            .await
            .map_err(|_| AgentError::Timeout)??;
        let mut reader = expect(&answer, SSH_AGENT_SIGN_RESPONSE)?;
        let signature = Vec::<u8>::decode(&mut reader)?;
        if !reader.is_finished() {
            return Err(AgentError::Malformed("trailing data".to_owned()));
        }
        Ok(signature)
    }

    async fn request(&mut self, message: &[u8]) -> Result<Vec<u8>, AgentError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let len = u32::try_from(message.len())
            .map_err(|_| AgentError::Malformed("request too large".to_owned()))?;
        let mut frame = len.to_be_bytes().to_vec();
        frame.extend_from_slice(message);
        self.stream.write_all(&frame).await?;
        let mut len = [0u8; 4];
        self.stream.read_exact(&mut len).await?;
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_MESSAGE_SIZE {
            return Err(AgentError::Malformed(format!("answer of {len} bytes")));
        }
        let mut answer = vec![0u8; len];
        self.stream.read_exact(&mut answer).await?;
        Ok(answer)
    }
}

fn expect(answer: &[u8], kind: u8) -> Result<&[u8], AgentError> {
    match answer.split_first() {
        Some((k, rest)) if *k == kind => Ok(rest),
        Some((&SSH_AGENT_FAILURE, _)) => Err(AgentError::Failure),
        Some((k, _)) => Err(AgentError::Malformed(format!("unexpected message {k}"))),
        None => Err(AgentError::Malformed("empty answer".to_owned())),
    }
}

/// Whether `$SSH_AUTH_SOCK` is reachable, and the keys its agent holds, for `mairu doctor`.
pub async fn probe(socket: &std::path::Path) -> Result<Vec<Identity>, AgentError> {
    let mut agent = SshAgentClient::connect(socket).await?;
    agent.identities().await
}

/// A registered ed25519 key and its signatures, for tests elsewhere.
#[cfg(test)]
pub mod test_support {
    const SEED: [u8; 32] = [8; 32];

    fn private() -> ssh_key::PrivateKey {
        let keypair = ssh_key::private::Ed25519Keypair::from_seed(&SEED);
        ssh_key::PrivateKey::new(ssh_key::private::KeypairData::Ed25519(keypair), "me@laptop")
            .unwrap()
    }

    pub fn key() -> super::RegisteredKey {
        super::RegisteredKey::parse(&private().public_key().to_openssh().unwrap(), false).unwrap()
    }

    /// A binary SSHSIG over the challenge's statement.
    pub fn sign(challenge: &crate::proto::AuthorizationChallenge) -> Vec<u8> {
        use ssh_encoding::Encode;
        let sig = ssh_key::SshSig::sign(
            &private(),
            super::NAMESPACE,
            ssh_key::HashAlg::Sha512,
            &challenge.statement,
        )
        .unwrap();
        let mut out = vec![];
        sig.encode(&mut out).unwrap();
        out
    }

    pub fn signed(
        challenge: &crate::proto::AuthorizationChallenge,
    ) -> crate::proto::AuthorizationResponse {
        crate::proto::AuthorizationResponse {
            challenge_id: challenge.challenge_id.clone(),
            result: Some(crate::proto::authorization_response::Result::Sshsig(sign(
                challenge,
            ))),
        }
    }

    pub fn declined(
        challenge: &crate::proto::AuthorizationChallenge,
    ) -> crate::proto::AuthorizationResponse {
        crate::proto::AuthorizationResponse {
            challenge_id: challenge.challenge_id.clone(),
            result: Some(crate::proto::authorization_response::Result::Declined(
                super::DECLINED_NO_SSH_AGENT.to_owned(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic keys for tests.
    const ED25519_SEED: [u8; 32] = [7; 32];
    const P256_SCALAR: [u8; 32] = [9; 32];
    const APPLICATION: &str = "ssh:";

    fn ed25519_private() -> ssh_key::PrivateKey {
        let keypair = ssh_key::private::Ed25519Keypair::from_seed(&ED25519_SEED);
        ssh_key::PrivateKey::new(ssh_key::private::KeypairData::Ed25519(keypair), "me@laptop")
            .unwrap()
    }

    fn ed25519_key() -> RegisteredKey {
        RegisteredKey::parse(&ed25519_private().public_key().to_openssh().unwrap(), false).unwrap()
    }

    fn sk_ed25519_key(uv: bool) -> RegisteredKey {
        let signing = ed25519_dalek::SigningKey::from_bytes(&ED25519_SEED);
        let public = ssh_key::public::SkEd25519::new(
            ssh_key::public::Ed25519PublicKey(signing.verifying_key().to_bytes()),
            APPLICATION,
        );
        let key = ssh_key::PublicKey::new(ssh_key::public::KeyData::SkEd25519(public), "yubikey");
        RegisteredKey::parse(&key.to_openssh().unwrap(), uv).unwrap()
    }

    fn sk_p256_key(uv: bool) -> RegisteredKey {
        let signing = p256::ecdsa::SigningKey::from_bytes(&P256_SCALAR.into()).unwrap();
        let point = signing.verifying_key().to_encoded_point(false);
        let public = ssh_key::public::SkEcdsaSha2NistP256::new(point, APPLICATION);
        let key = ssh_key::PublicKey::new(
            ssh_key::public::KeyData::SkEcdsaSha2NistP256(public),
            "spare",
        );
        RegisteredKey::parse(&key.to_openssh().unwrap(), uv).unwrap()
    }

    /// What a FIDO authenticator signs: SHA-256(application) || flags || counter || SHA-256(message).
    fn sk_signed(message: &[u8], flags: u8) -> Vec<u8> {
        use sha2::Digest;
        let mut data = sha2::Sha256::digest(APPLICATION).to_vec();
        data.push(flags);
        data.extend(42u32.to_be_bytes());
        data.extend(sha2::Sha256::digest(message));
        data
    }

    fn sk_trailer(blob: &mut Vec<u8>, flags: u8) {
        blob.push(flags);
        blob.extend(42u32.to_be_bytes());
    }

    fn key_blob(key: &RegisteredKey) -> Vec<u8> {
        use ssh_encoding::Encode;
        let mut blob = vec![];
        key.public.key_data().encode(&mut blob).unwrap();
        blob
    }

    fn string(out: &mut Vec<u8>, bytes: &[u8]) {
        use ssh_encoding::Encode;
        bytes.encode(out).unwrap();
    }

    /// The SSHSIG an SSH agent holding the sk-ssh-ed25519 key would produce over `statement`.
    fn sign_sk_ed25519(statement: &[u8], flags: u8, namespace: &str) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let signing = ed25519_dalek::SigningKey::from_bytes(&ED25519_SEED);
        let data = signed_data(namespace, statement);
        let sig = signing.sign(&sk_signed(&data, flags));
        let mut blob = vec![];
        string(&mut blob, b"sk-ssh-ed25519@openssh.com");
        string(&mut blob, &sig.to_bytes());
        sk_trailer(&mut blob, flags);
        sshsig(&key_blob(&sk_ed25519_key(false)), namespace, &blob)
    }

    fn sign_sk_p256(statement: &[u8], flags: u8) -> Vec<u8> {
        use p256::ecdsa::signature::Signer;
        let signing = p256::ecdsa::SigningKey::from_bytes(&P256_SCALAR.into()).unwrap();
        let data = signed_data(NAMESPACE, statement);
        let sig: p256::ecdsa::Signature = signing.sign(&sk_signed(&data, flags));
        let mut inner = vec![];
        let mpint = |out: &mut Vec<u8>, bytes: &[u8]| {
            use ssh_encoding::Encode;
            ssh_key::Mpint::from_positive_bytes(bytes)
                .unwrap()
                .encode(out)
                .unwrap();
        };
        mpint(&mut inner, &sig.r().to_bytes());
        mpint(&mut inner, &sig.s().to_bytes());
        let mut blob = vec![];
        string(&mut blob, b"sk-ecdsa-sha2-nistp256@openssh.com");
        string(&mut blob, &inner);
        sk_trailer(&mut blob, flags);
        sshsig(&key_blob(&sk_p256_key(false)), NAMESPACE, &blob)
    }

    fn signed_data(namespace: &str, statement: &[u8]) -> Vec<u8> {
        ssh_key::SshSig::signed_data(namespace, ssh_key::HashAlg::Sha512, statement).unwrap()
    }

    fn sshsig(key_blob: &[u8], namespace: &str, signature_blob: &[u8]) -> Vec<u8> {
        use ssh_encoding::Encode;
        let mut out = b"SSHSIG".to_vec();
        1u32.encode(&mut out).unwrap();
        string(&mut out, key_blob);
        string(&mut out, namespace.as_bytes());
        string(&mut out, b"");
        string(&mut out, b"sha512");
        string(&mut out, signature_blob);
        out
    }

    fn sign_ed25519(statement: &[u8], namespace: &str) -> Vec<u8> {
        use ssh_encoding::Encode;
        let sig = ssh_key::SshSig::sign(
            &ed25519_private(),
            namespace,
            ssh_key::HashAlg::Sha512,
            statement,
        )
        .unwrap();
        let mut out = vec![];
        sig.encode(&mut out).unwrap();
        out
    }

    fn binding(pid: u32) -> Binding {
        Binding {
            pid,
            start_time: 100,
            action: ACTION_ASSUME_ROLE,
            server_id: "contoso".to_owned(),
            rolespec: Some(crate::proto::Rolespec {
                role: "123456789012/Admin".to_owned(),
                assume_role: None,
            }),
            request_digest: [1; 32],
        }
    }

    const NOW: std::time::Duration = std::time::Duration::from_secs(1000);

    fn issue(
        store: &mut Challenges<()>,
        keys: &[RegisteredKey],
        binding: Binding,
    ) -> crate::proto::AuthorizationChallenge {
        store.issue(binding, keys, NOW, None).0
    }

    #[test]
    fn test_parse_keys() {
        let line = ed25519_key().to_openssh();
        assert!(line.starts_with("ssh-ed25519 "), "{line}");
        assert!(
            RegisteredKey::parse(&line, true)
                .unwrap_err()
                .contains("sk- keys only")
        );
        assert!(RegisteredKey::parse("ssh-ed25519 junk", false).is_err());
        let sk = sk_ed25519_key(true);
        assert!(sk.is_sk());
        let anchored = sk.to_anchor_line();
        assert!(anchored.starts_with("verify-required sk-ssh-ed25519@openssh.com "));
        assert_eq!(RegisteredKey::from_anchor_line(&anchored).unwrap(), sk);
        assert_eq!(
            RegisteredKey::from_anchor_line(&ed25519_key().to_anchor_line()).unwrap(),
            ed25519_key()
        );
        assert!(ed25519_key().fingerprint().starts_with("SHA256:"));
    }

    #[test]
    fn test_statement_serialization() {
        use prost::Message;
        let mut store = Challenges::<()>::new([5; 16]);
        let challenge = issue(&mut store, &[ed25519_key()], binding(1));
        let statement =
            crate::proto::AuthorizationStatement::decode(&*challenge.statement).unwrap();
        assert_eq!(statement.agent_instance_id, vec![5; 16]);
        assert_eq!(statement.nonce.len(), 32);
        assert_eq!(statement.peer_pid, 1);
        assert_eq!(statement.peer_start_time, 100);
        assert_eq!(statement.action, "assume-role");
        assert_eq!(statement.server_id, "contoso");
        assert_eq!(
            statement.rolespec.as_ref().unwrap().role,
            "123456789012/Admin"
        );
        assert_eq!(statement.request_digest, vec![1; 32]);
        assert_eq!(statement.expires_at, challenge.expires_at);
        assert_eq!(statement.encode_to_vec(), challenge.statement);
        assert_eq!(challenge.challenge_id.len(), 16);
        assert_eq!(
            challenge.key_fingerprints,
            vec![ed25519_key().fingerprint()]
        );
        assert_eq!(challenge.method, "ssh-agent");
        let again = issue(&mut store, &[ed25519_key()], binding(1));
        assert_ne!(again.statement, challenge.statement);
    }

    fn verify(
        store: &mut Challenges<()>,
        challenge: &crate::proto::AuthorizationChallenge,
        binding: &Binding,
        now: std::time::Duration,
        sig: &[u8],
        keys: &[RegisteredKey],
    ) -> Result<(), String> {
        let pending = store
            .take(&challenge.challenge_id)
            .ok_or("no such challenge")?;
        pending.verify(binding, now, sig, keys).map(|_| ())
    }

    #[test]
    fn test_verify_ed25519_and_single_use() {
        let keys = [ed25519_key()];
        let mut store = Challenges::<()>::new([0; 16]);
        let c = issue(&mut store, &keys, binding(1));
        let sig = sign_ed25519(&c.statement, NAMESPACE);
        verify(&mut store, &c, &binding(1), NOW, &sig, &keys).unwrap();
        assert_eq!(
            verify(&mut store, &c, &binding(1), NOW, &sig, &keys).unwrap_err(),
            "no such challenge"
        );
    }

    #[test]
    fn test_verify_refusals() {
        let keys = [ed25519_key()];
        let refused = |sign: &dyn Fn(&[u8]) -> Vec<u8>,
                       at: std::time::Duration,
                       retry: Binding,
                       keys: &[RegisteredKey]| {
            let mut store = Challenges::<()>::new([0; 16]);
            let c = issue(&mut store, &[ed25519_key()], binding(1));
            verify(&mut store, &c, &retry, at, &sign(&c.statement), keys).unwrap_err()
        };
        let good = |s: &[u8]| sign_ed25519(s, NAMESPACE);
        let late = NOW + CHALLENGE_LIFETIME;
        assert!(refused(&good, late, binding(1), &keys).contains("expired"));
        assert!(refused(&good, NOW, binding(2), &keys).contains("another process"));
        let mut other_start = binding(1);
        other_start.start_time = 101;
        assert!(refused(&good, NOW, other_start, &keys).contains("another process"));
        let mut other_request = binding(1);
        other_request.request_digest = [2; 32];
        assert!(refused(&good, NOW, other_request, &keys).contains("another request"));
        let mut other_action = binding(1);
        other_action.action = ACTION_USE_CREDENTIALS;
        assert!(refused(&good, NOW, other_action, &keys).contains("another request"));
        assert!(refused(&|s| sign_ed25519(s, "git"), NOW, binding(1), &keys).contains("namespace"));
        assert!(
            refused(&good, NOW, binding(1), &[sk_p256_key(false)])
                .contains("not by a registered key")
        );
        assert!(
            refused(
                &|s| sign_ed25519(&[s, b"x"].concat(), NAMESPACE),
                NOW,
                binding(1),
                &keys
            )
            .contains("does not verify")
        );
        assert!(
            refused(&|_| b"junk".to_vec(), NOW, binding(1), &keys).contains("not a valid SSHSIG")
        );
    }

    #[test]
    fn test_verify_sk_flags() {
        let check = |key: RegisteredKey, sign: &dyn Fn(&[u8]) -> Vec<u8>| {
            let keys = [key];
            let mut store = Challenges::<()>::new([0; 16]);
            let c = issue(&mut store, &keys, binding(1));
            verify(&mut store, &c, &binding(1), NOW, &sign(&c.statement), &keys)
        };
        let up = SK_FLAG_USER_PRESENT;
        let uv = SK_FLAG_USER_PRESENT | SK_FLAG_USER_VERIFIED;
        check(sk_ed25519_key(false), &|s| {
            sign_sk_ed25519(s, up, NAMESPACE)
        })
        .unwrap();
        assert!(
            check(sk_ed25519_key(false), &|s| sign_sk_ed25519(s, 0, NAMESPACE))
                .unwrap_err()
                .contains("user presence")
        );
        assert!(
            check(sk_ed25519_key(true), &|s| sign_sk_ed25519(s, up, NAMESPACE))
                .unwrap_err()
                .contains("user verification")
        );
        check(sk_ed25519_key(true), &|s| sign_sk_ed25519(s, uv, NAMESPACE)).unwrap();
        assert!(
            check(sk_ed25519_key(false), &|s| sign_sk_ed25519(s, up, "file"))
                .unwrap_err()
                .contains("namespace")
        );

        check(sk_p256_key(false), &|s| sign_sk_p256(s, up)).unwrap();
        assert!(
            check(sk_p256_key(false), &|s| sign_sk_p256(s, 0))
                .unwrap_err()
                .contains("user presence")
        );
        assert!(
            check(sk_p256_key(true), &|s| sign_sk_p256(s, up))
                .unwrap_err()
                .contains("user verification")
        );
        check(sk_p256_key(true), &|s| sign_sk_p256(s, uv)).unwrap();
        // Flags the authenticator did not sign.
        assert!(
            check(sk_ed25519_key(false), &|s| {
                let mut sig = sign_sk_ed25519(s, 0, NAMESPACE);
                let at = sig.len() - SK_TRAILER_SIZE;
                sig[at] = up;
                sig
            })
            .unwrap_err()
            .contains("does not verify")
        );
    }

    #[test]
    fn test_per_peer_limit_and_sweep() {
        let keys = [ed25519_key()];
        let mut store = Challenges::<u32>::new([0; 16]);
        let mut ids = vec![];
        for n in 0..6u32 {
            let at = NOW + std::time::Duration::from_secs(n.into());
            let (c, evicted) = store.issue(binding(1), &keys, at, Some(n));
            ids.push(c.challenge_id);
            let evicted: Vec<u32> = evicted.into_iter().filter_map(|c| c.guard).collect();
            match n {
                0..=3 => assert!(evicted.is_empty()),
                _ => assert_eq!(evicted, vec![n - 4]),
            }
        }
        assert_eq!(store.len(), 4);
        store.issue(
            binding(2),
            &keys,
            NOW + std::time::Duration::from_secs(6),
            None,
        );
        assert_eq!(store.len(), 5);
        assert!(store.take(&ids[0]).is_none());
        assert!(store.take(&ids[5]).is_some());
        let swept = store.sweep(NOW + CHALLENGE_LIFETIME + std::time::Duration::from_secs(4));
        assert_eq!(swept.len(), 3);
        assert_eq!(store.len(), 1);
        assert_eq!(store.clear().len(), 1);
        assert!(store.is_empty());
    }

    /// An in-process SSH agent holding one ed25519 key, or refusing to sign.
    async fn fake_agent(dir: &std::path::Path, refuse: bool) -> std::path::PathBuf {
        use ssh_encoding::{Decode, Encode};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let path = dir.join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let private = ed25519_private();
                    loop {
                        let mut len = [0u8; 4];
                        if stream.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        let mut msg = vec![0u8; u32::from_be_bytes(len) as usize];
                        stream.read_exact(&mut msg).await.unwrap();
                        let mut answer = vec![];
                        match msg[0] {
                            SSH_AGENTC_REQUEST_IDENTITIES => {
                                answer.push(SSH_AGENT_IDENTITIES_ANSWER);
                                1u32.encode(&mut answer).unwrap();
                                let mut blob = vec![];
                                private.public_key().key_data().encode(&mut blob).unwrap();
                                blob.encode(&mut answer).unwrap();
                                "me@laptop".encode(&mut answer).unwrap();
                            }
                            SSH_AGENTC_SIGN_REQUEST if !refuse => {
                                use signature::Signer;
                                let mut reader = &msg[1..];
                                let _blob = Vec::<u8>::decode(&mut reader).unwrap();
                                let data = Vec::<u8>::decode(&mut reader).unwrap();
                                let sig: ssh_key::Signature = private.try_sign(&data).unwrap();
                                let mut blob = vec![];
                                sig.encode(&mut blob).unwrap();
                                answer.push(SSH_AGENT_SIGN_RESPONSE);
                                blob.encode(&mut answer).unwrap();
                            }
                            _ => answer.push(SSH_AGENT_FAILURE),
                        }
                        let mut frame = (answer.len() as u32).to_be_bytes().to_vec();
                        frame.extend(answer);
                        stream.write_all(&frame).await.unwrap();
                    }
                });
            }
        });
        path
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mairu-ssh-agent-test-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn test_relay_signs_and_verifies() {
        let dir = temp_dir("sign");
        let socket = fake_agent(&dir, false).await;
        let keys = [ed25519_key()];
        let mut store = Challenges::<()>::new([0; 16]);
        let c = issue(&mut store, &keys, binding(1));
        let relay = Relay::new(Some(socket));
        let comment = parking_lot::Mutex::new(String::new());
        let resp = relay
            .respond(&c, |k| {
                *comment.lock() = k.to_owned();
                String::new()
            })
            .await;
        assert_eq!(*comment.lock(), "me@laptop");
        assert_eq!(resp.challenge_id, c.challenge_id);
        let Some(crate::proto::authorization_response::Result::Sshsig(sig)) = resp.result else {
            panic!("{resp:?}");
        };
        verify(&mut store, &c, &binding(1), NOW, &sig, &keys).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_relay_declines() {
        use crate::proto::authorization_response::Result as R;
        let dir = temp_dir("decline");
        let keys = [ed25519_key()];
        let mut store = Challenges::<()>::new([0; 16]);
        let c = issue(&mut store, &keys, binding(1));
        let declined = |r: crate::proto::AuthorizationResponse| match r.result {
            Some(R::Declined(d)) => d,
            other => panic!("{other:?}"),
        };

        assert_eq!(
            declined(Relay::new(None).respond(&c, |_| String::new()).await),
            "no-ssh-agent"
        );
        let stale = Relay::new(Some(dir.join("gone.sock")));
        assert_eq!(
            declined(stale.respond(&c, |_| String::new()).await),
            "no-ssh-agent"
        );

        let socket = fake_agent(&dir, true).await;
        let other = issue(&mut store, &[sk_p256_key(false)], binding(1));
        let relay = Relay::new(Some(socket.clone()));
        assert_eq!(
            declined(relay.respond(&other, |_| String::new()).await),
            "no-registered-key"
        );
        // A decline sticks for the rest of the command.
        assert_eq!(
            declined(relay.respond(&c, |_| String::new()).await),
            "no-registered-key"
        );
        let relay = Relay::new(Some(socket));
        assert_eq!(
            declined(relay.respond(&c, |_| String::new()).await),
            "sign-failed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_with_challenges_retries_with_the_response() {
        let dir = temp_dir("rounds");
        let socket = fake_agent(&dir, false).await;
        let keys = [ed25519_key()];
        let store = parking_lot::Mutex::new(Challenges::<()>::new([0; 16]));
        let relay = Relay::new(Some(socket));
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let result = relay
            .with_challenges(
                |_, _| String::new(),
                |response| {
                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let result = match response.and_then(|r| r.result.map(|x| (r.challenge_id, x)))
                    {
                        None => {
                            let c = issue(&mut store.lock(), &keys, binding(1));
                            Err(crate::proto::AuthorizationError::challenge(c).into_status())
                        }
                        Some((id, crate::proto::authorization_response::Result::Sshsig(sig))) => {
                            let pending = store.lock().take(&id).unwrap();
                            pending
                                .verify(&binding(1), NOW, &sig, &keys)
                                .map(|_| 42)
                                .map_err(tonic::Status::permission_denied)
                        }
                        Some(other) => panic!("{other:?}"),
                    };
                    async move { result }
                },
            )
            .await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);

        // Challenged every time: gives up after a few rounds.
        calls.store(0, std::sync::atomic::Ordering::SeqCst);
        let result: tonic::Result<()> = relay
            .with_challenges(
                |_, _| String::new(),
                |_| {
                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let c = issue(&mut store.lock(), &keys, binding(1));
                    async move { Err(crate::proto::AuthorizationError::challenge(c).into_status()) }
                },
            )
            .await;
        assert!(result.is_err());
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            MAX_ROUNDS + 1
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
