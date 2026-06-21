//! Chinese (`zh`) translation dictionary plus its private helper
//! string sets. The localized string values are intentionally non-ASCII;
//! only identifiers and comments stay in English.

use super::{Locale, TranslationDict};

/// R3 spec sync — Chinese error toast strings.
fn add_r3_error_keys_zh(dict: &mut TranslationDict) {
    dict.set(
        "error.agent.pairing_request_expired",
        "配对请求已过期 — 请重新发起配对并重新扫描。",
    );
    dict.set(
        "error.agent.proof_invalid",
        "证明签名验证失败 — 请重新签名后再试。",
    );
    dict.set(
        "error.agent.paused",
        "Agent 已暂停。请先恢复 Agent 再重试。",
    );
    dict.set(
        "error.agent.deactivated",
        "Agent 已永久停用。请重新配置一个新的 Agent。",
    );
    dict.set(
        "error.agent.accountability_grant_missing",
        "控制方问责授权缺失或已失效；请重新挂载授权后再试。",
    );
    dict.set(
        "error.agent.approval_already_consumed",
        "该 approval nonce 已被消费,请申请新的 approval。",
    );

    dict.set(
        "error.call.focus_unavailable_for_client",
        "所选媒体 focus 对此客户端不可用。请重试或离开通话。",
    );
    dict.set(
        "error.call.focus_mismatch",
        "媒体 focus 与通话状态不一致。请重新加入通话。",
    );
    dict.set(
        "error.call.unknown_focus_type",
        "未知的媒体 focus 类型,请将应用升级到兼容版本。",
    );
    dict.set(
        "error.call.token_issuer_unauthorised",
        "媒体 token 签发者不是 realm 当前的媒体服务。拒绝连接。",
    );
    dict.set(
        "error.call.participant_binding_invalid",
        "Participant binding 校验失败(签名/TTL/字段不一致)。",
    );
    dict.set(
        "error.call.participant_identity_unrecognised",
        "后端报告的 participant identity 不在通话状态列表中。Fail closed。",
    );
    dict.set(
        "error.call.session_focus_already_committed",
        "本通话的 session focus 已提交,请重新加入。",
    );
    dict.set(
        "error.call.e2ee_key_source_unauthorised",
        "拒绝接受来自非授权来源的媒体密钥 — 仅 MLS Exporter 派生密钥被接受。",
    );
    dict.set(
        "error.call.recording_artifact_pipeline_bypassed",
        "录制目标不是 Cokret 认证 blob — 拒绝录制。",
    );
    dict.set(
        "error.call.transcription_artifact_pipeline_bypassed",
        "转写目标不是 Cokret 认证 blob — 拒绝转写。",
    );
    dict.set(
        "error.call.desktop_media_unavailable",
        "桌面端通话尚未就绪(此版本无媒体传输)。请改用 Web 客户端发起本次通话。",
    );

    dict.set(
        "error.handle.homograph_forbidden",
        "该 handle 含有跨脚本或易混淆字符,无法注册。",
    );
    dict.set(
        "error.handle.script_mixed_warning",
        "警告:handle 混合了多种文字系统(例如 Latin + Cyrillic),将被拒绝。",
    );
    dict.set(
        "error.handle.nfc_normalization_warning",
        "Handle 已进行 Unicode 规范化(NFC),规范化结果将作为唯一形式。",
    );

    dict.set(
        "error.recovery.witness_revoke_lagging",
        "Recovery witness 撤销链落后 — 请等待 witness 链跟上。",
    );
    dict.set(
        "error.recovery.policy_mismatch",
        "Recovery policy 不匹配:服务器上的 policy 版本与请求不一致。",
    );
    dict.set(
        "error.recovery.challenge_proof_invalid",
        "Recovery 挑战证明验证失败。请重新采集证明后再试。",
    );

    // R3.3 (CKP-0011) — shareable object links (English dict). Error copy in
    // this dict follows the existing Chinese-first convention for `error.*`;
    // the dedicated zh dict carries the Chinese UI strings.
    dict.set("object_link.share", "Share link");
    dict.set("object_link.share_realm", "Share this Realm");
    dict.set("object_link.share_strand", "Share this Strand");
    dict.set("object_link.share_message", "Share this Message");
    dict.set("object_link.copy_https", "Copy link");
    dict.set("object_link.copy_app", "Copy \"open in app\" link");
    dict.set("object_link.copied", "Link copied");
    dict.set("object_link.open", "Open shared link");
    dict.set(
        "object_link.open_placeholder",
        "Paste a web+cokret: or https share link",
    );
    dict.set("object_link.opening", "Opening link\u{2026}");
    dict.set(
        "object_link.error.unavailable",
        "This link is unavailable or has expired.",
    );
    dict.set(
        "object_link.error.invalid",
        "That link format was not recognized.",
    );
}

/// Build Chinese translation dictionary.
pub fn chinese_translations() -> TranslationDict {
    let mut dict = TranslationDict::new(Locale::Zh);

    dict.set("app.title", "yougen");
    dict.set("nav.dashboard", "主页");
    dict.set("nav.timeline", "时间线");
    dict.set("nav.chat", "聊天");
    dict.set("nav.forum", "论坛");
    dict.set("nav.directory", "目录");
    dict.set("nav.notifications", "通知");
    dict.set("nav.settings", "设置");
    dict.set("nav.login", "登录");
    dict.set("nav.audit", "审计");
    dict.set("nav.devices", "设备");
    dict.set("nav.collaboration", "协作");
    dict.set("nav.contacts", "联系人");
    dict.set("nav.direct_messages", "私聊");
    dict.set("nav.new_realm_short", "领域");
    dict.set("nav.add_contact_short", "联系人");
    dict.set("direct.empty", "暂无私聊");
    dict.set("direct.sign_in", "登录后加载私聊");
    dict.set("direct.open", "打开私聊");
    dict.set("direct.unavailable", "暂不可发送");
    dict.set("contacts.empty", "暂无联系人");
    dict.set("contacts.sign_in", "登录后加载联系人");

    dict.set("login.server", "服务器");
    dict.set("login.connection_test", "连接测试");
    dict.set("login.server_url", "服务器地址");
    dict.set("login.test_connection", "测试连接");
    dict.set("login.account", "账户");
    dict.set("login.account_did", "账户 DID");
    dict.set("login.device_id", "设备 ID");
    dict.set("login.passkey", "Passkey 登录");
    dict.set("login.oidc", "OIDC 登录");
    dict.set("login.dev_login", "开发者登录");
    dict.set("login.session", "会话");
    dict.set("login.disconnected", "未连接");
    dict.set("login.connected", "已连接");
    dict.set("login.soft_logout", "软登出");
    dict.set("login.no_token", "无活跃令牌");
    dict.set("login.token_active", "令牌活跃");
    dict.set("login.refresh_token", "刷新令牌");
    dict.set("login.re_login", "重新登录");
    dict.set(
        "login.session_expired",
        "您的会话已过期。请重新登录以继续。",
    );

    dict.set("timeline.send", "发送");
    dict.set("timeline.reply", "回复");
    dict.set("timeline.react", "反应");
    dict.set("timeline.edit", "编辑");
    dict.set("timeline.redact", "撤回");
    dict.set("timeline.thread", "线程");
    dict.set("timeline.save", "保存");
    dict.set("timeline.cancel", "取消");
    dict.set("timeline.pending", "(待定)");
    dict.set("timeline.edited", "(已编辑)");
    dict.set("timeline.redacted", "[消息已撤回]");

    dict.set("common.loading", "加载中...");
    dict.set("common.error", "错误");
    dict.set("common.retry", "重试");
    dict.set("common.close", "关闭");
    dict.set("common.confirm", "确认");
    dict.set("common.cancel", "取消");
    dict.set("common.save", "保存");
    dict.set("common.delete", "删除");
    dict.set("common.edit", "编辑");
    dict.set("common.send", "发送");
    dict.set("common.refresh", "刷新");
    dict.set("common.back", "返回");
    dict.set("common.next", "下一步");
    dict.set("common.online", "在线");
    dict.set("common.offline", "离线");
    dict.set("common.reconnecting", "重连中");

    // R-i18n-002 mirrored keys.
    dict.set("topbar.search_placeholder", "跳转到 Realm、视图或操作...");
    dict.set("topbar.notifications", "通知");
    dict.set("topbar.new_space", "新建空间");
    dict.set("topbar.account_menu", "账号菜单");

    dict.set("login.continue", "继续");
    dict.set("login.working", "处理中...");
    dict.set("login.signed_in_as", "已登录为");

    dict.set("dashboard.home", "主页");
    dict.set("dashboard.notifications_label", "通知");
    dict.set("dashboard.notifications_delta_unread", "未读与待审批");
    dict.set("dashboard.notifications_delta_signin", "需要登录");
    dict.set("dashboard.realms_label", "Realm");
    dict.set("dashboard.realms_delta_search", "搜索或加入 Realm");
    dict.set("dashboard.realms_delta_signin", "登录后加载 Realm");
    dict.set("dashboard.workspace_setup", "Realm 设置");
    dict.set(
        "dashboard.workspace_setup_delta",
        "创建第一个 Realm 与初始策略",
    );
    dict.set("dashboard.onboarding", "引导");
    dict.set("dashboard.onboarding_steps", "4 步");
    dict.set("dashboard.onboarding_delta", "身份、设备与恢复方案");
    dict.set("dashboard.recent_realms", "最近 Realm");
    dict.set("dashboard.no_realms", "暂无 Realm");
    dict.set("dashboard.no_realms_help", "服务器尚未返回 Realm 列表。");
    dict.set("dashboard.no_session_help", "客户端不会展示占位 Realm。");
    // F-I18N-CLEAN-1: new keys synced with the en dict.
    dict.set("dashboard.no_notifications", "暂无通知");
    dict.set("dashboard.notifications_signin", "登录后加载通知");
    dict.set(
        "dashboard.notifications_empty_sub",
        "未读项、审批请求与提醒会显示在此处",
    );
    dict.set("chat.empty_discussions", "暂无可用讨论 track。");
    dict.set("chat.empty_messages", "尚无消息。");
    dict.set("chat.loading_messages", "正在加载讨论...");
    // F-CHAT-DEAD-UI-1: discussion settings panel copy synced with the en dict.
    dict.set("chat.settings.mute_notifications", "静音通知");
    dict.set("chat.settings.read_receipts", "已读回执");
    dict.set("chat.settings.shared_history", "共享历史");
    dict.set(
        "chat.settings.shared_history_hint",
        "Space 级别策略——在 Space 管理处设置。",
    );
    dict.set(
        "settings.muted_realms_empty",
        "未静音任何 Realm。在通知视图中静音吵闹 Realm。",
    );
    dict.set("realm_admin.no_members_loaded", "还没有成员。");
    dict.set(
        "realm_admin.members_empty_hint",
        "用上方的 + 按钮邀请第一位成员。",
    );
    dict.set("realm_admin.members_no_match", "没有匹配的成员。");
    dict.set(
        "realm_admin.invite_hint",
        "优先使用对方生成的邀请 locator 链接；如果对方允许被发现，也可以输入 handle 或 DID + server DID。",
    );

    dict.set("notifications.archived", "显示已归档");
    dict.set("notifications.mark_all_read", "全部标记已读");
    dict.set("notifications.empty_state", "暂无通知。");
    // F-NOTIF-VLIST-1: pagination button copy synced with the en dict.
    dict.set("notifications.showing", "已显示");
    dict.set("notifications.load_more", "加载更多");
    dict.set("directory.loading_more", "加载中…");
    dict.set("directory.load_more_realms", "加载更多 Realm");
    dict.set("directory.load_more_organizations", "加载更多组织");
    dict.set("directory.load_more_actors", "加载更多用户");

    dict.set("composer.send", "发送");
    dict.set("composer.encrypted_toggle", "本地加密");
    dict.set(
        "composer.plaintext_warning",
        "明文消息对所配置的服务器可见。",
    );

    dict.set("command_palette.realms", "Realm");
    dict.set("command_palette.jump_to", "跳转到");
    dict.set(
        "command_palette.empty",
        "未找到匹配的 Realm 或视图。按 Esc 关闭。",
    );
    dict.set("command_palette.close", "关闭 (Esc)");

    dict.set("mobile.filter_realms", "筛选 Realm...");
    dict.set("mobile.no_match", "未找到匹配 Realm。");

    // Kanban / Board view
    dict.set("kanban.board_header", "看板");
    dict.set("kanban.board_title", "看板");
    dict.set("kanban.board_hint", "拖动卡片到不同列即可移动。");
    dict.set("chat.send", "发送");
    dict.set("chat.send_secure", "加密发送");
    dict.set("chat.plaintext_blocked", "先输入消息内容再加密发送");
    dict.set("realm_admin.save_profile", "保存资料");
    dict.set("realm_admin.destroy_realm", "销毁 Realm");
    dict.set("realm_admin.archive_realm", "归档 Realm");
    dict.set("verify_device.refresh_trust", "刷新");
    dict.set("verify_device.verify_action", "验证");
    dict.set("verify_device.revoke_action", "撤销");
    dict.set("verify_device.revoke_confirm_title", "确认撤销此设备？");
    dict.set("verify_device.revoke_confirm_button", "确认撤销");
    dict.set("common.cancel_button", "取消");
    dict.set("common.refresh", "刷新");
    dict.set("common.save", "保存");
    dict.set("common.submit", "提交");
    dict.set("kanban.refresh_from_api", "从 API 刷新");
    dict.set("kanban.add_card", "添加卡片");
    dict.set("kanban.add_list", "添加列表");
    dict.set("kanban.save_card", "保存");
    dict.set("kanban.cancel_card", "取消");
    dict.set(
        "kanban.security_not_ready",
        "安全状态未就绪,请稍候重试后再写入该 Realm。",
    );
    dict.set("realm_admin.apply_policy", "应用策略");
    dict.set("realm_admin.grant_capability_move", "授予权限（Move）");
    dict.set("realm_admin.revoke_capability_move", "撤销权限（Move）");
    dict.set("realm_admin.admin_grant_title", "Realm 管理员");
    dict.set(
        "realm_admin.admin_grant_hint",
        "授予或撤销 ck.realm.admin 权限。以签名 capability 事件提交;待 soland reducer 投影后生效。",
    );
    dict.set("realm_admin.admin_subject_label", "管理员主体(DID)");
    dict.set("realm_admin.admin_grant_id_label", "Grant ID");
    dict.set(
        "realm_admin.admin_subject_required",
        "请填写要设为管理员的主体 DID",
    );
    dict.set(
        "realm_admin.admin_grant_id_required",
        "请填写要撤销的 Grant ID",
    );
    dict.set("realm_admin.admin_grant_button", "设为管理员");
    dict.set("realm_admin.admin_revoke_button", "撤销管理员");
    dict.set("realm_admin.refresh_members", "刷新");
    dict.set("realm_admin.kick_member", "踢出");
    dict.set("realm_admin.ban_member", "封禁");
    dict.set("realm_admin.kick_member_move", "踢出（Move）");
    dict.set("realm_admin.ban_member_move", "封禁（Move）");
    dict.set("realm_admin.rotate_epoch", "轮换 Epoch");
    dict.set("realm_admin.leave_realm", "退出");
    dict.set("directory.list_contacts", "列出");
    dict.set("directory.search_button", "搜索");
    dict.set("directory.resolve_selected", "解析选中");
    dict.set("settings.store_backup", "存储备份");
    dict.set("settings.register_push", "注册推送");
    dict.set("settings.unregister_push", "注销推送");
    // T1.3 - event signature / proof mode status display.
    dict.set("settings.proof_mode.label", "事件签名");
    dict.set(
        "settings.proof_mode.hint",
        "决定本设备提交事件时附加的 proof 类型。",
    );
    dict.set("settings.proof_mode.placeholder_dev", "开发占位");
    dict.set("settings.proof_mode.real_ed25519", "真实 Ed25519");
    dict.set("settings.proof_mode.external_signer", "外部 signer");
    dict.set(
        "settings.proof_mode.production",
        "未配置 signer（生产模式）",
    );

    // T5.2 — signer DID / key id / freshness panel
    dict.set("settings.signer.label", "活跃签名者");
    dict.set("settings.signer.freshness.label", "上次签名时间");
    dict.set("settings.signer.freshness.never", "尚未签名");
    dict.set("kanban.archive_action", "归档");
    dict.set("kanban.restore_action", "恢复");
    dict.set("kanban.archived_lists_header", "已归档列表");
    dict.set("kanban.archived_lists_empty", "暂无已归档列表。");
    dict.set("kanban.archived_cards_header", "已归档卡片");
    dict.set("kanban.archived_cards_empty", "暂无已归档卡片。");
    dict.set("kanban.move_queue_header", "Move 队列");
    dict.set("kanban.move_queue_empty", "本地没有排队的 Move。");

    // Directory view
    dict.set("directory.org_empty_body", "未找到组织，可尝试搜索。");
    dict.set("directory.actors_empty_body", "未找到 actor，可尝试搜索。");

    // Recovery view
    dict.set("recovery.title", "恢复");
    dict.set("recovery.recovery_key_section", "恢复密钥（24 词）");
    dict.set("recovery.social_section", "社交恢复");
    dict.set("mls_unlock.aria_label", "授权此设备");
    dict.set("mls_unlock.title", "授权此设备");
    dict.set("mls_unlock.subtitle", "优先使用已授权设备确认");
    dict.set(
        "mls_unlock.description",
        "此浏览器已经登录，但还不是可读取加密历史的已授权设备。Cokret v1 要求已有授权设备先批准新设备，然后才共享 MLS 历史密钥。",
    );
    dict.set("mls_unlock.approve_step_existing_title", "在已有设备上");
    dict.set(
        "mls_unlock.approve_step_existing_body",
        "打开 Settings -> Devices -> Pair new device，查看待审批请求，比对验证码后批准。",
    );
    dict.set("mls_unlock.approve_step_new_title", "在此浏览器上");
    dict.set(
        "mls_unlock.approve_step_new_body",
        "打开配对请求页面并保持可见，等待已有设备完成批准。",
    );
    dict.set(
        "mls_unlock.loading_hint",
        "批量恢复加密空间可能需要几秒钟，请保持此标签页打开。",
    );
    dict.set("mls_unlock.open_pairing", "显示配对请求");
    dict.set("mls_unlock.show_recovery_key", "改用恢复密钥");
    dict.set("mls_unlock.hide_recovery_key", "隐藏恢复密钥");
    dict.set(
        "mls_unlock.recovery_fallback_hint",
        "仅在无法使用任何已授权设备时使用。24 词恢复密钥会进入恢复路径，并在策略校验后解锁加密历史备份。",
    );
    dict.set("mls_unlock.placeholder", "24 词恢复密钥");
    dict.set("mls_unlock.button_idle", "用密钥解锁");
    dict.set("mls_unlock.button_busy", "正在解锁…");
    dict.set("mls_unlock.dismiss", "稍后处理");
    dict.set("mls_unlock.reopen", "授权此设备");
    dict.set(
        "mls_unlock.status.enter_passphrase",
        "输入 24 词恢复密钥以解锁加密历史。",
    );
    dict.set(
        "mls_unlock.status.invalid_recovery_key",
        "请完整输入创建备份时显示的 24 个恢复词。",
    );
    dict.set("mls_unlock.status.fetching", "正在查找加密历史备份…");
    dict.set("mls_unlock.status.restoring_prefix", "正在恢复");
    dict.set(
        "mls_unlock.status.restoring_suffix",
        "个加密备份，可能需要几秒钟。",
    );
    dict.set("mls_unlock.status.restored_prefix", "已恢复");
    dict.set("mls_unlock.status.restored_suffix", "个加密空间。");
    dict.set("mls_unlock.status.failed_suffix", "个失败");
    dict.set("mls_recovery_missing.aria_label", "此设备尚未拿到加密密钥");
    dict.set(
        "mls_recovery_missing.title",
        "此设备还没有这个 Realm 的密钥",
    );
    dict.set("mls_recovery_missing.subtitle", "当前无法在此打开加密内容");
    dict.set(
        "mls_recovery_missing.description",
        "这个 Realm 是端到端加密的。如果你刚接受邀请,密钥会在你加入时自动送达——无需输入任何凭证,刷新或等同步完成,新消息即可打开。你加入之前发的消息在任何设备上都无法打开——这是设计使然,任何恢复备份都解不开它们。恢复备份只用于找回你自己其他设备上的内容:请到 设置 → Recovery,生成 24 词恢复密钥——你的加密历史会自动备份到它名下。",
    );
    dict.set("mls_recovery_missing.button_dismiss", "关闭");

    // One-time account MLS secret backup prompt, mirroring mls_unlock.
    dict.set("mls_backup.aria_label", "备份加密历史");
    dict.set("mls_backup.title", "保护你的加密历史");
    dict.set("mls_backup.subtitle", "24 个恢复词");
    dict.set(
        "mls_backup.description",
        "你已在使用加密，但账号还没有加密历史恢复备份。创建一个 24 词恢复密钥后，新浏览器或新设备才能恢复同一份加密历史。",
    );
    dict.set(
        "mls_backup.description_existing",
        "你已在使用加密，但账号还没有加密历史恢复备份。请使用已经保存的 24 词恢复密钥来加密并上传备份。",
    );
    dict.set(
        "mls_backup.warning.passphrase_loss",
        "24 个恢复词出现后请立即保存。Cokret 不会保存它们；遗失后，已设置好的设备仍可继续使用，但新设备无法恢复这份加密历史。",
    );
    dict.set(
        "mls_backup.warning.existing_key",
        "恢复密钥不会上传；它只在本设备本地用于加密备份，然后才上传密文。",
    );
    dict.set("mls_backup.button_idle", "创建恢复密钥");
    dict.set("mls_backup.button_existing", "用恢复密钥备份");
    dict.set("mls_backup.button_retry", "重试备份");
    dict.set("mls_backup.button_busy", "正在备份…");
    dict.set("mls_backup.button_dismiss", "稍后提醒");
    dict.set("mls_backup.button_saved", "我已保存密钥");
    dict.set("mls_backup.button_done", "完成");
    dict.set("mls_backup.copy_key", "复制");
    dict.set("mls_backup.copy_key_done", "已复制 ✓");
    dict.set("mls_backup.download_key", "下载 .txt");
    dict.set("mls_backup.existing_key_label", "恢复密钥（24 词）");
    dict.set(
        "mls_backup.existing_key_placeholder",
        "输入你已经保存的 24 词恢复密钥",
    );
    dict.set(
        "mls_backup.existing_key_hint",
        "启用加密历史备份前，需要确认你仍然持有离线恢复密钥。",
    );
    dict.set("mls_backup.generated_key_label", "你的 24 词恢复密钥");
    dict.set(
        "mls_backup.generated_key_warning",
        "请现在保存这些词。关闭此提示后它们将不再显示。",
    );
    dict.set("mls_backup.status.uploading", "正在加密并上传备份…");
    dict.set(
        "mls_backup.status.created",
        "备份已创建。请立即保存这 24 个恢复词。",
    );
    dict.set("mls_backup.status.generate_failed", "恢复密钥生成失败：");
    dict.set(
        "mls_backup.status.invalid_recovery_key",
        "请输入完整的 24 词恢复密钥。",
    );

    // X11.1 - persisted MLS recovery key setup section.
    dict.set("settings.mls_recovery.title", "加密历史恢复");
    dict.set("settings.mls_recovery.status.loading", "正在检查备份状态…");
    dict.set(
        "settings.mls_recovery.status.no_local_secret",
        "尚未使用加密——在你发送加密消息或写入加密看板之前，没有可备份的内容。",
    );
    dict.set(
        "settings.mls_recovery.status.backed_up",
        "已备份——可使用你的 24 词恢复密钥恢复加密历史。",
    );
    dict.set(
        "settings.mls_recovery.status.not_backed_up",
        "未备份——请创建 24 词恢复密钥，以便新浏览器或新设备能够恢复你的加密历史。",
    );
    dict.set("settings.mls_recovery.submit", "创建 / 替换恢复词");

    // Space-admin view
    dict.set("realm_admin.title", "Realm 设置");
    dict.set("realm_admin.devices", "设备");
    dict.set("realm_admin.members", "成员");
    dict.set("realm_admin.access", "访问控制");
    dict.set("realm_admin.security_mls", "安全与 MLS");

    // Chat / Discussion view
    dict.set("chat.discussions_header", "Strand 讨论");
    dict.set("chat.users_header", "用户");
    dict.set("chat.settings_header", "设置");
    dict.set("chat.new_discussion", "新建讨论");
    dict.set("chat.new_strand", "新建 Strand");
    dict.set("chat.hide_list", "隐藏讨论列表");
    dict.set("chat.label.title", "标题");
    dict.set("chat.label.summary", "概述");
    dict.set("common.remove", "移除");
    dict.set("chat.call.voice", "发起语音通话");
    dict.set("chat.call.video", "发起视频通话");
    // T7.2 watch-level quick switch
    dict.set("chat.watch_level.prefix", "关注");
    dict.set("chat.watch_level.tooltip", "选择此 Strand 的通知频率。");
    dict.set("chat.watch_level.mentions_only", "仅 @ 我");
    dict.set("chat.watch_level.participating", "参与中");
    dict.set("chat.watch_level.all", "全部");
    dict.set("chat.watch_level.muted", "静音");
    dict.set("chat.watch_level.pending", "正在更新 watch level…");
    dict.set("chat.watch_level.saved", "watch level 已更新。");
    dict.set(
        "chat.watch_level.failed",
        "watch level 更新失败（已回滚）。",
    );
    // T7.3 handle reassignment context
    dict.set("chat.handle_reassigned.badge", "handle 已被重新分配");
    dict.set(
        "chat.handle_reassigned.tooltip",
        "撰写时记录的 handle 当前指向不同的 DID。请比对捕获的标签与当前发送者。",
    );
    dict.set("chat.binding_context.separator", " @ ");
    dict.set("chat.binding_context.details", "显示服务绑定");
    // T7.4 E2EE state
    dict.set("chat.crypto.decrypting", "解密中…");
    dict.set("chat.crypto.decrypt_failed", "解密失败");
    dict.set("chat.crypto.decrypt_failed_action", "前往恢复");
    dict.set("chat.crypto.key_missing", "尚未收到密钥");
    dict.set(
        "chat.crypto.key_missing_hint",
        "等待 Space 管理员或其他设备发送的 Welcome 消息。",
    );
    dict.set("chat.crypto.needs_verification", "发送方需要验证");
    dict.set("chat.mls.epoch", "MLS epoch");
    dict.set("chat.mls.key_package", "Key package");
    dict.set("chat.mls.welcome", "Welcome");
    // T7.5 layout adjustments
    dict.set("chat.tabs.settings", "设置");
    dict.set("chat.tabs.members", "成员");
    dict.set("chat.tabs.notifications", "通知");
    dict.set("chat.button.create", "创建");
    dict.set("chat.button.reply", "回复");
    dict.set("chat.button.react", "回应");
    dict.set("chat.button.redact", "撤回");
    dict.set("chat.you_badge", "我");
    // Member visual identity (member.badge.*)
    dict.set("member.badge.agent", "智能体");
    // Composer drag-and-drop attachments (A6.2)
    dict.set(
        "compose.drop_zone.hint",
        "将文件拖放到此处以附加,或点击「附加」",
    );
    dict.set("compose.upload_progress", "上传中…");
    dict.set("compose.upload_error", "上传失败");
    // Message shared pin and holder-private saved item actions.
    dict.set("message.pin", "钉选");
    dict.set("message.unpin", "取消钉选");
    dict.set("message.shared_pin", "共享钉选");
    dict.set("message.shared_unpin", "取消共享钉选");
    dict.set("message.shared_pin_pending", "正在共享钉选…");
    dict.set("message.shared_unpin_pending", "正在移除共享钉选…");
    dict.set("message.shared_pinned", "共享钉选已更新。");
    dict.set("message.shared_unpinned", "共享钉选已移除。");
    dict.set("message.private_save", "仅为我保存");
    dict.set("message.private_saved", "已为我保存");
    dict.set("pinned_bar.title", "共享钉选消息");
    dict.set("pinned_bar.empty", "暂无钉选消息。");
    dict.set("pinned_bar.scroll_to", "跳转到消息");
    // Actor-private Realm list pinning.
    dict.set("realm.pin", "置顶 Realm");
    dict.set("realm.unpin", "取消置顶 Realm");
    dict.set("realm.pinned", "已置顶 Realm");
    dict.set("realm.add_member", "添加成员");
    dict.set("realm.settings", "设置");
    dict.set("realm.pin_failed", "Realm 置顶 account-data 写入失败");
    dict.set("chat.empty.title", "暂无可用讨论 track");
    dict.set(
        "chat.empty.description",
        "该 Space 应该提供默认 Strand 的讨论 track。",
    );
    dict.set("chat.empty.create_button", "创建 Strand");

    // Notifications panel
    dict.set("notifications.feed_title", "通知流");
    dict.set("notifications.view.latest", "最新");
    dict.set("notifications.view.realm", "Realm");
    dict.set("notifications.view.type", "类型");
    dict.set("notifications.tooltip.settings", "通知设置");
    dict.set("notifications.tooltip.mark_all_read", "全部标为已读");
    dict.set("notifications.tooltip.show_archived", "显示已归档");
    dict.set("notifications.tooltip.hide_archived", "隐藏已归档");
    dict.set("notifications.tooltip.refresh", "刷新通知");
    dict.set(
        "notifications.filtered_body",
        "已加载的通知全部被归档、类型或空间静音规则过滤掉了。",
    );

    // Verify Device
    dict.set("verify_device.title", "设备验证");
    dict.set("verify_device.choose_method", "选择方式");
    dict.set("verify_device.qr_code", "二维码");
    dict.set("verify_device.sas_emoji", "SAS（表情）");
    dict.set("verify_device.qr_section", "二维码验证");
    dict.set("verify_device.qr_section_hint", "扫描或显示");
    dict.set("verify_device.sas_section", "SAS 验证");
    dict.set("verify_device.sas_section_hint", "表情对比");
    dict.set("verify_device.target_device_id", "目标设备 ID");
    dict.set("verify_device.target_device_placeholder", "要验证的设备 ID");
    dict.set("verify_device.generate_qr", "生成二维码");
    dict.set("verify_device.start_sas", "开始 SAS 验证");
    dict.set("verify_device.short_auth_string", "短认证串");

    // A6.4 - keyboard shortcut help overlay.
    dict.set("shortcuts.title", "键盘快捷键");
    dict.set("shortcuts.dismiss", "关闭");
    dict.set("shortcuts.list.help", "显示此快捷键面板");
    dict.set("shortcuts.list.dismiss", "关闭任何打开的对话框");
    dict.set("shortcuts.list.palette", "打开命令面板");
    dict.set("shortcuts.list.palette_mac", "打开命令面板 (macOS)");
    dict.set("shortcuts.list.send", "发送当前消息");
    // Personal blocklist (A5)
    dict.set("settings.privacy.title", "隐私");
    dict.set("settings.privacy.blocked_users.title", "已屏蔽的用户");
    dict.set(
        "settings.privacy.blocked_users.empty",
        "尚未屏蔽任何用户。在成员列表或消息行中屏蔽用户后，可在此管理。",
    );
    dict.set(
        "settings.privacy.blocked_users.did_placeholder",
        "要屏蔽的 DID",
    );
    dict.set(
        "settings.privacy.blocked_users.reason_placeholder",
        "原因（可选）",
    );
    dict.set("settings.privacy.blocked_users.add", "屏蔽");
    dict.set("settings.privacy.blocked_users.added", "已屏蔽");
    dict.set("settings.privacy.blocked_users.removed", "已取消屏蔽");
    dict.set("settings.privacy.blocked_users.duplicate", "已在屏蔽列表中");
    dict.set(
        "settings.privacy.blocked_users.did_required",
        "请先输入 DID。",
    );
    // F-BLOCKLIST-VALID-1: live format validation hints synced with the en dict.
    dict.set(
        "settings.privacy.blocked_users.did_invalid",
        "DID 必须以 did: 开头（如 did:web:alice.example）。",
    );
    dict.set("settings.privacy.unblock", "取消屏蔽");
    // A4b - avatar upload.
    dict.set("settings.avatar.title", "头像");
    dict.set("settings.avatar.upload", "上传新头像");
    dict.set("settings.avatar.clear", "清除头像");
    dict.set("settings.avatar.uploading", "上传中…");
    dict.set("settings.avatar.processing", "正在准备头像…");
    dict.set("settings.avatar.crop_ready", "调整裁剪后上传。");
    dict.set("settings.avatar.invalid_image", "所选文件不是图片。");
    dict.set("settings.avatar.upload_cropped", "上传裁剪后的头像");
    dict.set("settings.avatar.cancel_crop", "取消裁剪");
    dict.set("settings.avatar.zoom", "缩放");
    dict.set("settings.avatar.pan_x", "水平");
    dict.set("settings.avatar.pan_y", "垂直");
    dict.set("settings.avatar.error", "头像上传失败");
    // A6.1 - global cross-space message search.
    dict.set("search.title", "搜索消息");
    dict.set("search.placeholder", "在所有空间中搜索消息…");
    dict.set("search.results.empty", "输入查询以在所有空间中搜索。");
    dict.set("search.results.loading", "搜索中…");
    dict.set("search.results.error", "搜索失败");
    dict.set("search.no_results", "未找到匹配项。");
    dict.set("search.result.snippet", "摘要");
    dict.set("topbar.search_button", "打开搜索");
    dict.set("shortcuts.list.search", "打开全局消息搜索");
    dict.set("member.block", "屏蔽此用户");
    dict.set("member.block_confirm.title", "屏蔽此用户？");
    dict.set(
        "member.block_confirm.body",
        "其消息将被占位符替代。您可随时在 设置 → 隐私 中取消屏蔽。",
    );
    dict.set("member.block_confirm.confirm", "屏蔽");
    dict.set("timeline.blocked_user", "[已屏蔽用户]");
    dict.set("timeline.show_anyway", "仍要查看");

    // A3 (round 28): rich content renderer strings.
    dict.set("content.code.copy", "复制");
    dict.set("content.image.broken", "图片不可用");
    dict.set("content.video.unsupported", "您的浏览器不支持内嵌视频。");
    dict.set("content.audio.unsupported", "您的浏览器不支持内嵌音频。");
    dict.set("content.attachment.download", "下载");

    // T7.1 - friendly product terminology for Chinese.
    dict.set(
        "friendly.identifier.placeholder",
        "john:example.com 或 did:web:...",
    );
    dict.set(
        "friendly.identifier.placeholder_multiline",
        "alice:example.com\nbob:example.com",
    );
    dict.set("friendly.identifier.label", "成员标识");
    dict.set(
        "friendly.identifier.hint",
        "输入 user:domain.com 形式的句柄，或粘贴完整 DID。",
    );
    dict.set("friendly.identifier.handle_or_email", "句柄或 DID");
    dict.set("friendly.member.automated", "自动化成员");
    dict.set("friendly.member.bot", "机器人");
    dict.set("friendly.member.human", "成员");
    dict.set("friendly.member.agent_badge", "机器人");
    dict.set("friendly.identifier.technical", "协议标识符");
    dict.set("friendly.identifier.show_technical", "显示技术详情");
    dict.set("friendly.identifier.hide_technical", "隐藏技术详情");
    dict.set("friendly.security.encrypted", "已加密");
    dict.set("friendly.security.encrypted_short", "加密");
    dict.set("friendly.draft.label", "草稿");
    dict.set("friendly.sync.state", "同步状态");
    dict.set("friendly.sync.synced", "已同步");
    dict.set("friendly.sync.pending", "同步中…");
    dict.set("friendly.sync.frontier", "同步状态");

    // Realm is the security boundary (members / policy / federation / E2EE);
    // Space is the container (navigation / boards / lists).
    dict.set("friendly.realm", "Realm");
    dict.set("friendly.realm.short", "Realm");
    dict.set(
        "friendly.realm.description",
        "安全边界 — 成员、策略、联邦与加密都在这一层治理。",
    );
    dict.set("friendly.realm.security_class", "安全边界");
    dict.set("friendly.realm.security_class.standard", "标准安全");
    dict.set("friendly.realm.security_class.high_assurance", "高保障");
    dict.set("friendly.realm.settings", "Realm 设置");
    dict.set(
        "friendly.realm.settings.subtitle",
        "策略、成员、联邦与端到端加密",
    );
    dict.set("friendly.realm.switcher", "切换 Realm");
    dict.set("friendly.realm.ref_label", "Realm");
    dict.set("friendly.space", "空间");
    dict.set("friendly.space.short", "空间");
    dict.set(
        "friendly.space.description",
        "导航容器 — 看板、列表与分区都在 Realm 之内。",
    );
    dict.set("friendly.space.container_class", "导航容器");
    dict.set("friendly.space.settings", "空间设置");
    dict.set("friendly.space.settings.subtitle", "导航、排序与展示");
    dict.set("friendly.discussion.realm_ref", "Realm");
    dict.set(
        "friendly.discussion.realm_ref.hint",
        "该讨论所属的 Realm（安全边界）。",
    );

    dict.set("profile_gate.title", "此服务器暂不支持该功能");
    dict.set(
        "profile_gate.body",
        "当前服务器尚未提供该视图所需的能力。请尝试其他服务器或联系管理员。",
    );
    dict.set("profile_gate.friendly.minimal_client", "基础客户端");
    dict.set("profile_gate.friendly.kanban_mvp", "看板");
    dict.set("profile_gate.friendly.chat_mvp", "讨论");
    dict.set("profile_gate.friendly.full_client", "完整客户端");
    dict.set("profile_gate.friendly.e2ee_client", "加密通讯");
    dict.set("profile_gate.friendly.unknown", "客户端功能");

    dict.set("nav.developer", "开发者工具");
    dict.set("developer.title", "开发者工具");
    dict.set("developer.subtitle", "协议诊断与审计");
    dict.set("developer.section.schemas", "Schemas 与事件类型");
    dict.set("developer.section.profiles", "服务器 Profile");
    dict.set("developer.section.events", "原始事件日志");
    dict.set("developer.section.conformance", "协议合规");
    dict.set("developer.section.protocol_version", "协议版本");
    dict.set(
        "developer.hint",
        "以下信息面向开发者和运维人员。终端用户无需阅读。",
    );
    dict.set("developer.profile.required", "所需 Profile id");
    dict.set("developer.profile.advertised", "服务器声明");
    dict.set("developer.event.kind", "事件类型");
    dict.set("developer.schema.id", "Schema id");

    // R3 spec sync (b47ff6ec) — Chinese error toast translations.
    add_r3_error_keys_zh(&mut dict);

    // Contacts / invite-receive policy / realm invite-from-contacts.
    add_contacts_keys_zh(&mut dict);

    dict
}

/// Chinese translations for the contacts surfaces — mirrors
/// [`add_contacts_keys`].
fn add_contacts_keys_zh(dict: &mut TranslationDict) {
    // ── ContactsPanel ─────────────────────────────────────────────────
    dict.set("contacts.title", "联系人");
    dict.set("contacts.add_button", "添加联系人");
    dict.set("contacts.load_error", "加载联系人失败:{error}");
    dict.set("contacts.retry", "重试");
    dict.set("contacts.loading", "正在加载联系人…");
    dict.set("contacts.empty_title", "还没有联系人");
    dict.set(
        "contacts.empty_hint",
        "点击“添加联系人”发送一个好友请求,对方接受后就会出现在这里。",
    );
    dict.set("contacts.empty_add", "添加联系人");

    // ── ContactNewPanel ───────────────────────────────────────────────
    dict.set("contacts.new.title", "添加联系人");
    dict.set("contacts.new.subtitle", "需对方同意");
    dict.set(
        "contacts.new.intro",
        "输入对方的 DID 或 handle 发送好友请求。成为好友默认既能私聊、也允许对方拉你入群(像微信好友一样)。如需更严格,可在下面取消勾选。",
    );
    dict.set("contacts.new.target_label", "对方 DID 或 handle");
    dict.set(
        "contacts.new.recipient_service_label",
        "对方所在服务器(跨服务器添加时填)",
    );
    dict.set(
        "contacts.new.recipient_service_placeholder",
        "did:web:ps.bob.example(同服务器留空)",
    );
    dict.set(
        "contacts.new.recipient_service_hint",
        "对方在另一台服务器(Principal Server)时填它的 service DID;同服务器留空即可。",
    );
    dict.set("contacts.new.scope_label", "好友权限(普通好友默认两项都开)");
    dict.set("contacts.new.scope_empty", "至少需要选择一项权限。");
    dict.set("contacts.new.message_label", "附言(可选)");
    dict.set("contacts.new.message_placeholder", "打个招呼…");
    dict.set("contacts.new.sending", "正在发送请求…");
    dict.set("contacts.new.sent", "请求已发送,等待对方接受。");
    dict.set("contacts.new.send_failed", "发送失败:{error}");
    dict.set("contacts.new.submit", "发送请求");
    dict.set("contacts.new.submit_busy", "发送中…");

    // ── scope_label ───────────────────────────────────────────────────
    dict.set("contacts.scope.direct_message", "私聊(可以给我发私信)");
    dict.set("contacts.scope.invite", "可邀请我入群");
    dict.set("contacts.scope.voice_call", "语音通话");
    dict.set("contacts.scope.video_call", "视频通话");
    dict.set("contacts.shared_scopes", "共享权限:");

    // ── ContactRow ────────────────────────────────────────────────────
    dict.set("contacts.state.pending_incoming", "等待你处理");
    dict.set("contacts.state.pending_outgoing", "等待对方接受");
    dict.set("contacts.state.accepted", "已是联系人");
    dict.set("contacts.state.rejected", "已拒绝");
    dict.set("contacts.state.tombstoned", "已删除");
    dict.set("contacts.state.blocked", "已拉黑");
    dict.set("contacts.action.accept", "接受");
    dict.set("contacts.action.reject", "拒绝");
    dict.set("contacts.action.withdraw", "撤回");
    dict.set("contacts.action.message", "发消息");
    dict.set("contacts.action.call_voice", "语音通话");
    dict.set("contacts.action.call_video", "视频通话");
    dict.set("contacts.action.block", "拉黑");
    dict.set("contacts.action.accepting", "正在接受…");
    dict.set("contacts.action.rejecting", "正在拒绝…");
    dict.set("contacts.action.withdrawing", "正在撤回…");
    dict.set("contacts.action.blocking", "正在拉黑…");
    dict.set("contacts.dm.opening", "正在打开私聊…");
    dict.set("contacts.dm.not_ready", "私聊尚未就绪,请稍后再试。");
    dict.set("contacts.dm.open_failed", "打开私聊失败:{error}");
    dict.set("contacts.block.confirm_title", "确定拉黑该联系人?");
    dict.set(
        "contacts.block.confirm_body",
        "拉黑后会删除该联系人,并阻止对方再次向你发送请求或邀请。",
    );
    dict.set("contacts.block.confirm_button", "确认拉黑");
    dict.set("contacts.block.cancel", "取消");
    dict.set("contacts.action_failed", "操作失败:{error}");

    // ── InvitePolicySettingsCard ──────────────────────────────────────
    dict.set("invite_policy.title", "谁可以邀请我");
    dict.set("invite_policy.loading", "加载中…");
    dict.set(
        "invite_policy.intro",
        "选择哪些来源可以邀请你加入群组。不在允许范围内的邀请会按下面的规则丢弃或暂存待审。",
    );
    dict.set(
        "invite_policy.load_failed",
        "未能从服务器读取现有策略(将使用默认值):{error}",
    );
    dict.set("invite_policy.kinds_title", "允许的邀请来源");
    dict.set("invite_policy.kind.consent_grant", "联系人(已同意的好友)");
    dict.set("invite_policy.kind.locator_ref", "邀请链接");
    dict.set("invite_policy.kind.shared_realm", "同群成员");
    dict.set("invite_policy.kind.handle_claim", "知道我 handle 的人");
    dict.set(
        "invite_policy.kind.same_principal_server",
        "同一服务器的用户",
    );
    dict.set("invite_policy.kind.explicit_address", "任何知道我地址的人");
    dict.set(
        "invite_policy.explicit_label",
        "“任何知道我地址的人”的处理方式",
    );
    dict.set("invite_policy.handle_label", "通过 handle 邀请时的处理方式");
    dict.set("invite_policy.handle_allowed_domains", "允许的 handle 域名");
    dict.set("invite_policy.handle_blocked_domains", "屏蔽的 handle 域名");
    dict.set(
        "invite_policy.handle_hint",
        "公开 handle 会让别人更容易找到你。域名列表留空表示不额外限制；服务器仍可能施加更严格的最低要求。",
    );
    dict.set("invite_policy.explicit.drop", "直接丢弃");
    dict.set("invite_policy.explicit.quarantine", "暂存待审");
    dict.set("invite_policy.explicit.notify", "通知我");
    dict.set("invite_policy.unknown_prefix", "未知来源的邀请将被");
    dict.set("invite_policy.unknown_drop", "直接丢弃");
    dict.set("invite_policy.unknown_quarantine", "暂存待审");
    dict.set("invite_policy.unknown_suffix", "。");
    dict.set("invite_policy.disclosure_title", "回执");
    dict.set("invite_policy.disclosure_toggle", "让联系人知道邀请结果");
    dict.set(
        "invite_policy.discovery_disclosure_toggle",
        "让通过 handle 找到我的人知道邀请结果",
    );
    dict.set(
        "invite_policy.disclosure_hint",
        "对陌生人(低信任来源)始终不回执,避免暴露你是否在线或是否接受邀请。",
    );
    dict.set("invite_policy.server_caps_title", "服务器最低要求");
    dict.set("invite_policy.server_caps_empty", "服务器未公布额外限制。");
    dict.set("invite_policy.blocked_title", "已屏蔽的邀请者");
    dict.set("invite_policy.blocked_empty", "没有被屏蔽的邀请者。");
    dict.set("invite_policy.unblock", "移除");
    dict.set(
        "invite_policy.unblocked_hint",
        "已从屏蔽列表移除,记得点击保存。",
    );
    dict.set("invite_policy.saving", "正在保存…");
    dict.set("invite_policy.saved", "已保存。");
    dict.set("invite_policy.save_failed", "保存失败:{error}");
    dict.set("invite_policy.save", "保存");
    dict.set("invite_policy.save_busy", "保存中…");

    // ── realm-admin: invite from contacts ─────────────────────────────
    dict.set("realm_admin.invite_from_contacts", "从联系人添加");
    dict.set("realm_admin.invite_recommended", "推荐");
    dict.set("realm_admin.invite_loading_contacts", "正在加载联系人…");
    dict.set(
        "realm_admin.invite_contacts_failed",
        "加载联系人失败:{error}",
    );
    dict.set("realm_admin.invite_no_contacts", "还没有可邀请的联系人。");
    dict.set("realm_admin.invite_unauthorized", "对方未授权邀请");
    dict.set(
        "realm_admin.invite_none_eligible",
        "没有可邀请的联系人(缺少同意凭证)。",
    );
    dict.set("realm_admin.invite_sending", "正在邀请 {total} 位联系人…");
    dict.set("realm_admin.invite_sent", "已邀请 {ok} 位联系人(待接受)。");
    dict.set(
        "realm_admin.invite_partial",
        "已邀请 {ok}/{total} 位联系人;部分失败:{error}",
    );
    dict.set("realm_admin.invite_selected", "邀请所选联系人");
    dict.set("realm_admin.invite_divider", "或邀请陌生人(粘贴邀请链接)");
    dict.set("realm_admin.invite_bad_server", "无效的服务器地址:{error}");
}
