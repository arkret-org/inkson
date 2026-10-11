#[test]
fn shared_authority_objects_keep_the_application_wire_bytes() {
    let (commit, handoff) = arkret_test_kit::authority_objects::objects();
    let commit: arkret_sdk::RealmCommit =
        serde_json::from_slice(&serde_json::to_vec(&commit).unwrap()).unwrap();
    let handoff: arkret_sdk::RealmAuthorityHandoff =
        serde_json::from_slice(&serde_json::to_vec(&handoff).unwrap()).unwrap();
    arkret_test_kit::authority_objects::assert_canonical_objects(&commit, &handoff);
}
