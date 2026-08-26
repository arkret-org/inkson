// Current-v1 test carriers. This is deliberately an exact schema identity
// table: E2E mocks must exercise the same intersection rule as production
// clients and must not fall back to operation-id-only advertisement.
const HTTP_BINDINGS = new Map([
  ["ak.edge.push.command.register_device", ["schemas/push-operations.schema.json#/$defs/push_register_device_request_body", "schemas/push-operations.schema.json#/$defs/push_register_device_outcome", "typed_response"]],
  ["ak.edge.push.command.unregister_device", ["schemas/push-operations.schema.json#/$defs/push_unregister_device_request_body", "schemas/push-operations.schema.json#/$defs/push_unregister_device_outcome", "typed_response"]],
  ["ak.find.directory.read.describe", [undefined, "schemas/service-describe.schema.json", "service_describe"]],
  ["ak.find.directory.read.list_handles_for_subject", ["schemas/directory-operations.schema.json#/$defs/directory_list_handles_for_subject_request_body", "schemas/list-handles-for-subject-response.schema.json", "typed_response"]],
  ["ak.find.directory.read.resolve_handle", ["schemas/directory-operations.schema.json#/$defs/directory_resolve_handle_request_body", "schemas/directory-operations.schema.json#/$defs/directory_handle_resolution_outcome", "typed_response"]],
  ["ak.find.directory.read.resolve_realm", ["schemas/directory-operations.schema.json#/$defs/directory_resolve_realm_request_body", "schemas/directory-operations.schema.json#/$defs/directory_realm_resolution_outcome", "typed_response"]],
  ["ak.find.directory.read.search_actors", ["schemas/directory-operations.schema.json#/$defs/directory_search_actors_request_body", "schemas/directory-operations.schema.json#/$defs/directory_actor_search_outcome", "typed_response"]],
  ["ak.find.directory.read.search_organizations", ["schemas/directory-operations.schema.json#/$defs/directory_search_organizations_request_body", "schemas/directory-operations.schema.json#/$defs/directory_organization_search_outcome", "typed_response"]],
  ["ak.find.directory.read.search_realms", ["schemas/directory-operations.schema.json#/$defs/directory_search_realms_request_body", "schemas/directory-operations.schema.json#/$defs/directory_realm_search_outcome", "typed_response"]],
  ["ak.gate.account.command.pair_device", ["schemas/agent-operations.schema.json#/$defs/account_device_pair_request_body", "schemas/agent-operations.schema.json#/$defs/account_device_pair_outcome", "typed_response"]],
  ["ak.gate.account.command.register", ["schemas/account-operations.schema.json#/$defs/account_register_request_body", "schemas/account-operations.schema.json#/$defs/account_register_outcome", "typed_response"]],
  ["ak.gate.account.command.revoke_session", ["schemas/account-operations.schema.json#/$defs/session_revoke_request_body", "schemas/account-operations.schema.json#/$defs/session_revoke_outcome", "typed_response"]],
  ["ak.open.invite_locator.read.resolve", ["schemas/principal-locator.schema.json#/$defs/principal_locator_resolve_request_body", "schemas/principal-locator.schema.json", "typed_response"]],
  ["ak.open.mimi.command.notify", ["schemas/mimi-operations.schema.json#/$defs/mimi_notify_request_body", "schemas/mimi-operations.schema.json#/$defs/mimi_notify_outcome", "typed_response"]],
  ["ak.open.mimi.command.proxy_download", ["schemas/mimi-operations.schema.json#/$defs/mimi_proxy_download_request_body", "schemas/mimi-operations.schema.json#/$defs/mimi_proxy_download_outcome", "typed_response"]],
  ["ak.open.mimi.command.report_abuse", ["schemas/mimi-operations.schema.json#/$defs/mimi_report_abuse_request_body", "schemas/mimi-operations.schema.json#/$defs/mimi_report_abuse_outcome", "typed_response"]],
  ["ak.open.mimi.command.request_consent", ["schemas/mimi-operations.schema.json#/$defs/mimi_request_consent_request_body", "schemas/mimi-operations.schema.json#/$defs/mimi_request_consent_outcome", "typed_response"]],
  ["ak.open.mimi.command.submit_message", ["schemas/mimi-operations.schema.json#/$defs/mimi_submit_message_request_body", "schemas/mimi-operations.schema.json#/$defs/mimi_submit_message_outcome", "typed_response"]],
  ["ak.open.mimi.command.update_consent", ["schemas/mimi-operations.schema.json#/$defs/mimi_update_consent_request_body", "schemas/mimi-operations.schema.json#/$defs/mimi_update_consent_outcome", "typed_response"]],
  ["ak.open.mimi.command.update_room", ["schemas/mimi-operations.schema.json#/$defs/mimi_room_update_request_body", "schemas/mimi-operations.schema.json#/$defs/mimi_room_update_outcome", "typed_response"]],
  ["ak.open.mimi.exchange.request_key_material", ["schemas/mimi-operations.schema.json#/$defs/mimi_key_material_request_body", "schemas/mimi-operations.schema.json#/$defs/mimi_key_material_outcome", "typed_response"]],
  ["ak.open.mimi.read.group_info", [undefined, "schemas/mimi-operations.schema.json#/$defs/mimi_group_info_outcome", "typed_response"]],
  ["ak.open.mimi.read.identifiers", ["schemas/mimi-operations.schema.json#/$defs/mimi_identifier_query_request_body", "schemas/mimi-operations.schema.json#/$defs/mimi_identifier_query_outcome", "typed_response"]],
  ["ak.open.mimi.read.provider_directory", [undefined, "schemas/mimi-interop.schema.json", "schema_resource"]],
  ["ak.root.identity.read.resolve", ["schemas/service-operation-dtos.schema.json#/$defs/IdentityResolveRequestBody", "schemas/service-operation-dtos.schema.json#/$defs/IdentityResolveOutcome", "typed_response"]],
  ["ak.root.identity.recovery_policy.command.publish", ["schemas/recovery-policy.schema.json#/$defs/recovery_policy_publish_request", "schemas/recovery-policy.schema.json#/$defs/recovery_policy_publish_outcome", "schema_resource"]],
  ["ak.root.identity.recovery_policy.resource.get", [undefined, "schemas/recovery-policy.schema.json#/$defs/recovery_policy_active_outcome", "schema_resource"]],
  ["ak.root.identity.registry.read.describe", [undefined, "schemas/service-describe.schema.json", "service_describe"]],
  ["ak.self.account.command.update_profile", ["schemas/account-operations.schema.json#/$defs/account_update_profile_request_body", "schemas/account-operations.schema.json#/$defs/account_update_profile_outcome", "typed_response"]],
  ["ak.self.account.read.describe", [undefined, "schemas/service-describe.schema.json", "service_describe"]],
  ["ak.self.account.read.viewer", [undefined, "schemas/account-operations.schema.json#/$defs/account_view", "typed_response"]],
  ["ak.self.account.stream.subscribe", [undefined, "schemas/account-subscribe-frame.schema.json", "event_stream"]],
  ["ak.self.authz.grants.read.effective", [undefined, "schemas/service-operation-dtos.schema.json#/$defs/GrantList", "typed_response"]],
  ["ak.self.authz.invites.read.list", [undefined, "schemas/authz-operations.schema.json#/$defs/authz_invite_list", "typed_response"]],
  ["ak.self.authz.read.check", ["schemas/service-operation-dtos.schema.json#/$defs/AuthzCheckRequestBody", "schemas/service-operation-dtos.schema.json#/$defs/AuthzCheckOutcome", "typed_response"]],
  ["ak.self.blob.resource.get", [undefined, undefined, "binary_stream"]],
  ["ak.self.blob.upload.create", ["schemas/blob-operations.schema.json#/$defs/blob_upload_request_body", "schemas/blob-operations.schema.json#/$defs/blob_upload_outcome", "typed_response"]],
  ["ak.self.circle.command.archive", ["schemas/circle-operations.schema.json#/$defs/circle_archive_request_body", "schemas/circle-operations.schema.json#/$defs/circle_view", "typed_response"]],
  ["ak.self.circle.command.create", ["schemas/circle-operations.schema.json#/$defs/circle_create_request_body", "schemas/circle-operations.schema.json#/$defs/circle_view", "typed_response"]],
  ["ak.self.circle.command.restore", ["schemas/circle-operations.schema.json#/$defs/circle_restore_request_body", "schemas/circle-operations.schema.json#/$defs/circle_view", "typed_response"]],
  ["ak.self.circle.command.rotate_scope", [undefined, "schemas/circle-operations.schema.json#/$defs/circle_scope_rotate_outcome", "typed_response"]],
  ["ak.self.circle.command.tombstone", ["schemas/circle-operations.schema.json#/$defs/circle_tombstone_request_body", "schemas/circle-operations.schema.json#/$defs/circle_view", "typed_response"]],
  ["ak.self.circle.member.command.add", ["schemas/circle-operations.schema.json#/$defs/circle_member_request_body", "schemas/circle-operations.schema.json#/$defs/circle_membership_outcome", "typed_response"]],
  ["ak.self.circle.member.resource.delete", ["schemas/circle-operations.schema.json#/$defs/circle_member_delete_request_body", "schemas/circle-operations.schema.json#/$defs/circle_membership_outcome", "typed_response"]],
  ["ak.self.circle.read.list", [undefined, "schemas/circle-operations.schema.json#/$defs/circle_list", "typed_response"]],
  ["ak.self.circle.resource.get", [undefined, "schemas/circle-operations.schema.json#/$defs/circle_view", "typed_response"]],
  ["ak.self.contact.command.request", ["schemas/contact-operations.schema.json#/$defs/contact_operation_request", "schemas/contact-operations.schema.json#/$defs/contact_request_outcome", "typed_response"]],
  ["ak.self.contact.command.respond", ["schemas/contact-operations.schema.json#/$defs/contact_respond_request", "schemas/contact-operations.schema.json#/$defs/contact_respond_outcome", "typed_response"]],
  ["ak.self.contact.command.tombstone", ["schemas/contact-operations.schema.json#/$defs/contact_tombstone_request", "schemas/contact-operations.schema.json#/$defs/contact_tombstone_outcome", "typed_response"]],
  ["ak.self.contact.read.list", [undefined, "schemas/contact-operations.schema.json#/$defs/contact_list", "typed_response"]],
  ["ak.self.device_messages.command.ack", ["schemas/service-operation-dtos.schema.json#/$defs/DeviceMessagesAckRequestBody", "schemas/service-operation-dtos.schema.json#/$defs/DeviceMessagesAckOutcome", "typed_response"]],
  ["ak.self.device_messages.command.send", ["schemas/service-operation-dtos.schema.json#/$defs/DeviceMessagesSendRequestBody", "schemas/service-operation-dtos.schema.json#/$defs/DeviceMessagesSendOutcome", "typed_response"]],
  ["ak.self.device_messages.read.list", [undefined, "schemas/service-operation-dtos.schema.json#/$defs/DeviceMessagesGetOutcome", "typed_response"]],
  ["ak.self.direct_conversation.read.resolve", ["schemas/direct-conversation-operations.schema.json#/$defs/direct_conversation_resolve_request", "schemas/direct-conversation-operations.schema.json#/$defs/direct_conversation_resolve_outcome", "typed_response"]],
  ["ak.self.events.command.submit", ["schemas/service-operation-dtos.schema.json#/$defs/EventsSubmitRequestBody", "schemas/service-operation-dtos.schema.json#/$defs/SelfEventsSubmitOutcome", "typed_response"]],
  ["ak.self.events.read.describe", ["schemas/service-operation-dtos.schema.json#/$defs/EventsDescribeRequestBody", "schemas/service-describe.schema.json", "service_describe"]],
  ["ak.self.events.read.scan", ["schemas/service-operation-dtos.schema.json#/$defs/EventsQueryPostRequestBody", "schemas/service-operation-dtos.schema.json#/$defs/EventsQueryOutcome", "typed_response"]],
  ["ak.self.events.stream.subscribe", [undefined, "schemas/events-subscribe-frame.schema.json", "event_stream"]],
  ["ak.self.invite_receive_policy.resource.get", [undefined, "schemas/invite-receive-policy.schema.json", "typed_response"]],
  ["ak.self.invite_receive_policy.resource.replace", ["schemas/invite-receive-policy.schema.json", "schemas/invite-receive-policy.schema.json", "typed_response"]],
  ["ak.self.keys.backups.read.list", [undefined, "schemas/keys-operations.schema.json#/$defs/keys_backups_list", "typed_response"]],
  ["ak.self.keys.backups.resource.replace", ["schemas/key-backup.schema.json", "schemas/keys-operations.schema.json#/$defs/keys_backups_replace_outcome", "typed_response"]],
  ["ak.self.keys.command.claim", ["schemas/keys-operations.schema.json#/$defs/keys_claim_request_body", "schemas/keys-operations.schema.json#/$defs/keys_claim_outcome", "typed_response"]],
  ["ak.self.keys.read.lookup", ["schemas/keys-operations.schema.json#/$defs/keys_query_request_body", "schemas/keys-operations.schema.json#/$defs/keys_query_outcome", "typed_response"]],
  ["ak.self.keys.upload.create", ["schemas/keys-operations.schema.json#/$defs/keys_upload_request_body", "schemas/keys-operations.schema.json#/$defs/keys_upload_outcome", "typed_response"]],
  ["ak.self.media.read.ice_config", ["schemas/media-operations.schema.json#/$defs/media_ice_config_request_body", "schemas/ice-config-response.schema.json", "typed_response"]],
  ["ak.self.moderation.command.report", ["schemas/moderation-report.schema.json#/$defs/moderation_report_request_body", "schemas/service-operation-dtos.schema.json#/$defs/ModerationReportOutcome", "typed_response"]],
  ["ak.self.signal.command.send", ["schemas/signal-envelope.schema.json", "schemas/service-operation-dtos.schema.json#/$defs/SignalSubmitOutcome", "typed_response"]],
  ["ak.self.space.read.list", [undefined, "schemas/service-operation-dtos.schema.json#/$defs/ProjectionSpaceList", "typed_response"]],
  ["ak.self.strand.read.list", [undefined, "schemas/service-operation-dtos.schema.json#/$defs/ProjectionStrandList", "typed_response"]],
  ["ak.server.read.describe", [undefined, "schemas/service-describe.schema.json", "service_describe"]],
]);

export function currentHttpOperationBindings(operationIds) {
  return operationIds.map((operationId) => {
    const definition = HTTP_BINDINGS.get(operationId);
    if (!definition) {
      throw new Error(`missing current-v1 HTTP binding fixture for ${operationId}`);
    }
    const [requestSchema, responseSchema, successShape] = definition;
    return {
      operation_id: operationId,
      binding_kind: "http_json",
      preference: 100,
      ...(requestSchema === undefined ? {} : { request_schema_ref: requestSchema }),
      ...(responseSchema === undefined ? {} : { response_schema_ref: responseSchema }),
      error_schema_ref: "schemas/http-error-envelope.schema.json",
      success_shape_kind: successShape,
    };
  });
}

export function currentHttpDescribeBindings(operationIds, baseUrl) {
  return {
    operation_bindings: currentHttpOperationBindings(operationIds),
    supported_bindings: [
      {
        kind: "http_json",
        ...(baseUrl === undefined ? {} : { base_url: baseUrl }),
        operations: [...operationIds],
        extension_profile_required: null,
      },
    ],
  };
}
