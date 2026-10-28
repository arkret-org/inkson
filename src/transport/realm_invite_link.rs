//! Client-owned Realm invitation credentials and ordinary producer submission.

use arkret_models_collaboration::governance::realm_invite_link::*;
use arkret_sdk::{
    AccountId, ActorId, AuthorityLocatorSource, RealmId, RealmInviteLinkId, RealmJoinCandidate,
    RealmJoinCandidateServiceKind,
};

/// Kept only in this component session. The durable queue contains the public Event alone.
#[derive(Clone)]
pub(crate) struct PendingRealmInviteLink {
    pub(crate) credential: RealmInviteLinkToken,
    event: arkret_sdk::AuthoredEvent,
    pub(crate) accepted: bool,
}

impl PendingRealmInviteLink {
    pub(crate) fn share_url(&self, landing: &str) -> anyhow::Result<zeroize::Zeroizing<String>> {
        anyhow::ensure!(
            self.accepted,
            "Link creation is awaiting authority acceptance"
        );
        let landing = url::Url::parse(landing)?;
        anyhow::ensure!(
            landing.scheme() == "https"
                && landing.username().is_empty()
                && landing.password().is_none()
                && landing.query().is_none()
                && landing.fragment().is_none(),
            "A share landing must be a plain HTTPS URL"
        );
        let token = self.credential.encode()?;
        let mut address = arkret_sdk::ParsedAddress {
            realm: arkret_sdk::RealmRef::RealmId(
                self.credential
                    .realm_id
                    .as_str()
                    .trim_start_matches("ak:realm:")
                    .into(),
            ),
            strand: None,
            message: None,
            action: arkret_sdk::AddressAction::Join,
            address_link_kind: arkret_sdk::AddressLinkKind::Invite,
            token: Some(token.to_string()),
        };
        let result =
            zeroize::Zeroizing::new(arkret_sdk::build_https_landing(landing.as_str(), &address));
        if let Some(token) = address.token.as_mut() {
            use zeroize::Zeroize as _;
            token.zeroize();
        }
        Ok(result)
    }
}

pub(crate) fn parse_realm_invite_link(input: &str) -> anyhow::Result<RealmInviteLinkToken> {
    let address = arkret_sdk::parse_address(input)
        .map_err(|_| anyhow::anyhow!("Invalid Realm invitation link"))?;
    anyhow::ensure!(
        address.address_link_kind == arkret_sdk::AddressLinkKind::Invite && address.is_realm(),
        "Expected a Realm invitation link"
    );
    let arkret_sdk::RealmRef::RealmId(token) = address.realm else {
        anyhow::bail!("Invitation requires a canonical Realm identity")
    };
    let realm = RealmId::new(format!("ak:realm:{token}"))?;
    let encoded = zeroize::Zeroizing::new(
        address
            .token
            .ok_or_else(|| anyhow::anyhow!("Invitation credential is missing"))?,
    );
    RealmInviteLinkToken::decode(&encoded, &realm)
        .map_err(|_| anyhow::anyhow!("Invalid Realm invitation credential"))
}

impl super::TransportClient {
    pub(crate) async fn prepare_realm_invite_link(
        &self,
        account: &AccountId,
        realm: &RealmId,
        lifetime_seconds: u32,
        max_uses: u32,
    ) -> anyhow::Result<PendingRealmInviteLink> {
        anyhow::ensure!(
            max_uses > 0 && lifetime_seconds >= 60,
            "Choose a positive use allowance and a lifetime of at least one minute"
        );
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *seed)
            .map_err(|_| anyhow::anyhow!("Secure invitation entropy unavailable"))?;
        let secret = RealmInviteLinkSecret::from_seed(*seed);
        let payload = RealmInviteLinkCreatePayload {
            public_key: arkret_signatures::realm_invite_link::realm_invite_link_public_key(&secret),
            expires_at: crate::clock::now_utc_millis()
                + chrono::Duration::seconds(i64::from(lifetime_seconds)),
            max_uses,
        };
        let operation = crate::operation::TypedOperationBuilder::new_for_actor::<
            arkret_sdk::event_spec::RealmInviteLinkCreate,
        >(
            arkret_sdk::ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            ActorId::account(account.clone()),
            payload,
        )
        .build_sdk_event("inkson")?;
        let event = self
            .event_submitter()?
            .author_for_direct_submission(&operation)
            .await?;
        let station = self.describe_cached().await?.service_id.clone();
        let hints = vec![RealmJoinCandidate {
            service_kind: RealmJoinCandidateServiceKind::Station,
            service_id: station,
            endpoint_url: None,
            source: AuthorityLocatorSource::Invite,
        }];
        Ok(PendingRealmInviteLink {
            credential: RealmInviteLinkToken {
                schema: RealmInviteLinkToken::SCHEMA.into(),
                realm_id: realm.clone(),
                realm_invite_link_id: RealmInviteLinkId::from_event_id(&event.event_id),
                secret_seed: secret,
                authority_locator_hints: hints,
            },
            event,
            accepted: false,
        })
    }

    /// Retries retain this exact original Event and seed, even after an unknown delivery outcome.
    pub(crate) async fn publish_realm_invite_link(
        &self,
        pending: &mut PendingRealmInviteLink,
        account: &AccountId,
    ) -> anyhow::Result<crate::models::EventSubmissionProgress> {
        anyhow::ensure!(
            pending.event.actor_id.as_account_id() == Some(account),
            "Invitation belongs to another account"
        );
        let mut outcomes = self
            .event_submitter()?
            .submit_signed_sdk_events_in_order(std::slice::from_ref(&pending.event))
            .await?;
        let outcome = outcomes
            .pop()
            .ok_or_else(|| anyhow::anyhow!("Creation has no accepted outcome"))?;
        anyhow::ensure!(
            outcome.is_committed() && outcome.event_id == pending.event.event_id.as_str(),
            "Creation is not accepted"
        );
        pending.accepted = true;
        Ok(outcome)
    }

    pub(crate) async fn preview_realm_invite_link(
        &self,
        credential: &RealmInviteLinkToken,
        account: &AccountId,
    ) -> anyhow::Result<arkret_sdk::SelfRealmJoinPreviewResponseBody> {
        let request_id = arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms());
        let proof = arkret_signatures::realm_invite_link::sign_realm_invite_link_proof(
            &credential.secret_seed,
            &credential.realm_id,
            &credential.realm_invite_link_id,
            account,
            &request_id,
            false,
        )?;
        let request = arkret_sdk::SelfRealmJoinPreviewRequestBody {
            request_id,
            target: link_target(credential),
            link_proof: Some(proof),
        };
        Ok(self
            .sdk_http_client()?
            .self_realm_join_preview(&request)
            .await?)
    }

    pub(crate) async fn accept_realm_invite_link(
        &self,
        credential: &RealmInviteLinkToken,
        account: &AccountId,
    ) -> anyhow::Result<crate::models::EventSubmissionProgress> {
        credential.validate()?;
        let request_id = arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms());
        let preview_proof = arkret_signatures::realm_invite_link::sign_realm_invite_link_proof(
            &credential.secret_seed,
            &credential.realm_id,
            &credential.realm_invite_link_id,
            account,
            &request_id,
            false,
        )?;
        let prepared = self
            .sdk_http_client()?
            .self_realm_join_prepare(&arkret_sdk::SelfRealmJoinPrepareRequestBody {
                request_id: request_id.clone(),
                target: link_target(credential),
                intent: arkret_sdk::RealmJoinIntent::InviteLinkAccept {
                    realm_invite_link_id: credential.realm_invite_link_id.clone(),
                    link_proof: preview_proof,
                },
            })
            .await?;
        anyhow::ensure!(
            prepared.authority_bundle.current_assertion.expires_at > crate::clock::now_utc(),
            "Join authority assertion expired"
        );
        let proof = arkret_signatures::realm_invite_link::sign_realm_invite_link_proof(
            &credential.secret_seed,
            &credential.realm_id,
            &credential.realm_invite_link_id,
            account,
            &request_id,
            true,
        )?;
        let payload = RealmInviteLinkAcceptPayload {
            realm_invite_link_id: credential.realm_invite_link_id.clone(),
            subject_account_id: account.clone(),
            request_id,
            link_proof: proof,
        };
        let operation = crate::operation::TypedOperationBuilder::new_for_actor::<
            arkret_sdk::event_spec::RealmInviteLinkAccept,
        >(
            arkret_sdk::ScopeRef::Realm {
                realm_id: credential.realm_id.clone(),
            },
            ActorId::account(account.clone()),
            payload,
        )
        .build_sdk_event("inkson")?;
        self.event_submitter()?.submit_sdk_event(&operation).await
    }

    pub(crate) async fn revoke_realm_invite_link(
        &self,
        realm: &RealmId,
        link: &RealmInviteLinkId,
        account: &AccountId,
    ) -> anyhow::Result<crate::models::EventSubmissionProgress> {
        let operation = crate::operation::TypedOperationBuilder::new_for_actor::<
            arkret_sdk::event_spec::RealmInviteLinkRevoke,
        >(
            arkret_sdk::ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            ActorId::account(account.clone()),
            RealmInviteLinkRevokePayload {
                realm_invite_link_id: link.clone(),
            },
        )
        .build_sdk_event("inkson")?;
        self.event_submitter()?.submit_sdk_event(&operation).await
    }

    pub(crate) async fn realm_invite_link_views(
        &self,
        realm: &RealmId,
    ) -> anyhow::Result<Vec<RealmInviteLinkView>> {
        let snapshot = self
            .sdk_http_client()?
            .realm_state_snapshot_head(realm)
            .await?;
        Ok(realm_invite_link_views(&snapshot)?)
    }
}

fn link_target(credential: &RealmInviteLinkToken) -> arkret_sdk::RealmJoinTarget {
    arkret_sdk::RealmJoinTarget {
        realm_id: credential.realm_id.clone(),
        invite_id: None,
        authority_locator_hints: credential.authority_locator_hints.clone(),
        realm_invite_link_id: Some(credential.realm_invite_link_id.clone()),
    }
}
