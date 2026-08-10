#![cfg(target_arch = "wasm32")]

use arkret_sdk::{MessageCryptoDecrypt, MessageCryptoUnavailable};
use inkson::crypto::LocalMlsDevice;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000001";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000002";
const CAROL_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000003";
const DAVE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000004";
const GROUP_ID: &[u8] = b"ak:realm:AxfS5lL34ar8evkrjkj2VnQ9TZaIIN2algll426mYRJE";

#[wasm_bindgen_test]
fn removed_member_cannot_decrypt_new_epoch_and_failures_are_distinct() {
    let mut alice = LocalMlsDevice::new("did:web:alice.example", ALICE_DEVICE).unwrap();
    let mut bob = LocalMlsDevice::new("did:web:bob.example", BOB_DEVICE).unwrap();
    let mut carol = LocalMlsDevice::new("did:web:carol.example", CAROL_DEVICE).unwrap();

    alice.create_group(GROUP_ID).unwrap();
    let add_bob = alice
        .add_member(&bob.key_package_record().unwrap())
        .unwrap();
    bob.join_from_welcome(&add_bob.welcome).unwrap();
    let add_carol = alice
        .add_member(&carol.key_package_record().unwrap())
        .unwrap();
    bob.apply_commit(&add_carol.commit).unwrap();
    carol.join_from_welcome(&add_carol.welcome).unwrap();

    let pre_remove = alice
        .encrypt_message(
            "ak:message:A6u77rrmwcqnlGOsjJ1NCtyWmSQNe4IqYUz4mjELtyso",
            b"before remove",
        )
        .unwrap();
    assert!(matches!(
        bob.decrypt_or_preserve(pre_remove).unwrap(),
        MessageCryptoDecrypt::Plaintext { .. }
    ));

    let remove = alice
        .remove_member_by_principal("did:web:bob.example")
        .unwrap();
    for proposal in &remove.proposals {
        bob.apply_proposal(proposal).unwrap();
        carol.apply_proposal(proposal).unwrap();
    }
    bob.apply_commit(&remove.commit).unwrap();
    carol.apply_commit(&remove.commit).unwrap();

    let post_remove = alice
        .encrypt_message(
            "ak:message:AQKPg68zbJImnDqlj1CYc3otm32z4cR6NCjKfy5qS5xU",
            b"after remove",
        )
        .unwrap();
    assert!(matches!(
        carol.decrypt_or_preserve(post_remove.clone()).unwrap(),
        MessageCryptoDecrypt::Plaintext { .. }
    ));
    assert!(matches!(
        bob.decrypt_or_preserve(post_remove.clone()).unwrap(),
        MessageCryptoDecrypt::Encrypted {
            reason: MessageCryptoUnavailable::Removed,
            ..
        }
    ));

    let mut never_joined = LocalMlsDevice::new("did:web:never.example", DAVE_DEVICE).unwrap();
    assert!(matches!(
        never_joined
            .decrypt_or_preserve(post_remove.clone())
            .unwrap(),
        MessageCryptoDecrypt::Encrypted {
            reason: MessageCryptoUnavailable::NoSession,
            ..
        }
    ));

    let mut independent = LocalMlsDevice::new("did:web:dave.example", DAVE_DEVICE).unwrap();
    independent.create_group(GROUP_ID).unwrap();
    let wrong_key = independent
        .encrypt_message(
            "ak:message:AxNcKZEEPR7EFcSKxQ_Lptlgx8iJpZeZqrrfTAafbPbw",
            b"wrong key",
        )
        .unwrap();
    assert!(matches!(
        carol.decrypt_or_preserve(wrong_key).unwrap(),
        MessageCryptoDecrypt::Encrypted {
            reason: MessageCryptoUnavailable::KeyUnavailable(_),
            ..
        }
    ));

    let mut damaged = post_remove;
    damaged.payload.ciphertext.push('A');
    assert!(carol.decrypt_or_preserve(damaged).is_err());
}
