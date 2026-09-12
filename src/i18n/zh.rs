//! Chinese (`zh`) translation dictionary plus its private helper
//! string sets. The localized string values are intentionally non-ASCII;
//! only identifiers and comments stay in English.

use super::{TranslationDict, UiLocale};

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
        "代理的所有者授权缺失或已过期。请重新连接该授权,然后重试。",
    );
    dict.set(
        "error.agent.approval_already_consumed",
        "该 approval nonce 已被消费,请申请新的 approval。",
    );

    dict.set(
        "error.call.focus_unavailable_for_client",
        "此通话的媒体连接在当前应用中不可用。请重试,或退出通话后重新加入。",
    );
    dict.set(
        "error.call.focus_mismatch",
        "通话连接信息与通话状态不同步。请退出并重新加入通话。",
    );
    dict.set(
        "error.call.unknown_focus_type",
        "此通话使用了当前应用不支持的连接方式。请将应用更新到最新版本。",
    );
    dict.set(
        "error.call.token_issuer_unauthorised",
        "通话的访问令牌并非来自此 Realm 当前的媒体服务,连接已被拒绝。",
    );
    dict.set(
        "error.call.participant_binding_invalid",
        "某位参与者的通话凭证未通过校验,无法加入。",
    );
    dict.set(
        "error.call.participant_id_unrecognised",
        "服务器上报了一位不在此通话中的参与者。出于安全考虑,已拒绝连接。",
    );
    dict.set(
        "error.call.e2ee_key_source_unauthorised",
        "通话加密密钥来自不受信任的来源,已被拒绝。密钥只能来自群组自身的加密通道。",
    );
    dict.set(
        "error.call.recording_artifact_pipeline_bypassed",
        "录制目标不是经过验证的 Arkret 存储位置,已拒绝录制。",
    );
    dict.set(
        "error.call.transcription_artifact_pipeline_bypassed",
        "转写目标不是经过验证的 Arkret 存储位置,已拒绝转写。",
    );
    dict.set(
        "error.call.media_service_binding_uncovered",
        "此 Realm 尚未批准该通话使用的媒体服务,已拒绝加入。请联系管理员检查通话设置。",
    );
    dict.set(
        "error.call.media_plaintext_service_not_authorised",
        "此媒体服务无权处理未加密的媒体内容,连接已被拒绝。",
    );
    dict.set(
        "error.call.mls_governance_binding_stale",
        "该通话的授权记录已过期,与当前媒体策略不符,连接已被拒绝。请重新加入通话。",
    );
    dict.set(
        "error.call.desktop_media_unavailable",
        "此版本的桌面端通话功能尚未就绪。请改用网页版发起本次通话。",
    );
    dict.set(
        "error.invite.live_target_occupied",
        "该用户在此 Realm 中已有一条有效邀请，未重复创建。",
    );

    dict.set(
        "error.recovery.policy_mismatch",
        "Recovery policy 不匹配:服务器上的 policy 版本与请求不一致。",
    );
    dict.set(
        "error.recovery.challenge_proof_invalid",
        "Recovery 挑战证明验证失败。请重新采集证明后再试。",
    );

    // Shareable object links.
    dict.set("object_link.open", "打开分享链接");
    dict.set(
        "object_link.open_placeholder",
        "粘贴 web+arkret: 或 https 分享链接",
    );
    dict.set("object_link.opening", "正在打开链接…");
    dict.set("object_link.error.unavailable", "此链接不可用或已过期。");
    dict.set("object_link.error.invalid", "无法识别此链接格式。");
}

/// Generic API-error copy — zh counterparts of en.rs `add_generic_error_keys`.
fn add_generic_error_keys_zh(dict: &mut TranslationDict) {
    dict.set("error.generic", "与服务器通信时出现问题。请重试。");
    dict.set(
        "error.network_unavailable",
        "无法连接服务器。请检查网络连接,然后重试。",
    );
    dict.set(
        "error.server_format_mismatch",
        "服务器已响应，但当前应用无法读取其数据格式。请刷新或更新应用后重试。",
    );
    dict.set(
        "error.server_unavailable",
        "服务器当前不可用。请检查服务器地址,或稍等片刻后重试。",
    );
    dict.set("error.session_expired", "登录已过期。请重新登录以继续。");
    dict.set(
        "error.device_not_authorized",
        "此设备未获得该操作的授权。请在已登录的设备上授权此设备,然后重试。",
    );
    dict.set("error.rate_limited", "请求过于频繁。请稍等片刻,然后重试。");
    dict.set(
        "error.invite_locator_unavailable",
        "此邀请链接已失效，可能已过期或被撤销。请让对方在设置中重新生成邀请链接，并在 15 分钟内使用。",
    );
    dict.set(
        "error.not_found",
        "服务器找不到你要查看的内容。它可能已被移动或删除。请刷新后重试。",
    );
    dict.set(
        "error.permission_denied",
        "你没有执行此操作的权限。请让 Realm 所有者或管理员检查你的权限。",
    );
    dict.set(
        "error.unsupported_profile",
        "此 Realm 使用了当前应用或服务器不支持的 profile。请更新不支持该 profile 的组件后重试。",
    );
    dict.set(
        "error.unsupported_protocol_data",
        "此操作使用了当前应用或服务器不支持的协议数据类型。请更新不支持该类型的组件后重试。",
    );
    dict.set(
        "error.invalid_protocol_data",
        "服务器拒绝了不符合当前协议的数据。请刷新后重试；如果问题持续，请报告此问题。",
    );
    dict.set(
        "error.realm_state_conflict",
        "此 Realm 存在影响该操作的未解决状态冲突。请先解决或修复冲突的 Realm 状态。",
    );
}

/// Build Chinese translation dictionary.
pub fn chinese_translations() -> TranslationDict {
    let mut dict = TranslationDict::new(UiLocale::Zh);

    dict.set("nav.dashboard", "主页");
    dict.set("nav.directory", "目录");
    dict.set("nav.notifications", "通知");
    dict.set("nav.settings", "设置");
    dict.set("nav.files", "文件");
    dict.set("nav.collaboration", "协作");
    dict.set("nav.contacts", "联系人");
    dict.set("direct.unavailable", "暂不可发送");
    dict.set("contacts.empty", "暂无联系人");
    dict.set("contacts.sign_in", "登录后加载联系人");
    dict.set("sidebar.search_realms", "搜索 Realm");
    dict.set("sidebar.search_contacts", "搜索联系人");
    dict.set("sidebar.search", "搜索");
    dict.set("sidebar.realms_empty", "尚未加载 Realm");
    dict.set("sidebar.realms_sign_in", "登录后加载 Realm");
    dict.set("sidebar.realms_no_results", "没有匹配的 Realm");

    dict.set("directory.tab.organizations", "组织");
    dict.set("directory.tab.actors", "成员");

    dict.set("mls_backup.button_confirm_saved", "我已安全保存");
    dict.set("mls_backup.button_regenerate", "重新生成");
    dict.set("mls_backup.confirm_key_label", "确认恢复密钥");
    dict.set("mls_backup.confirm_key_placeholder", "再次输入恢复密钥");
    dict.set(
        "mls_backup.confirm_key_hint",
        "请再次输入以确认恢复密钥已正确保存。",
    );
    dict.set(
        "mls_backup.status.confirm_mismatch",
        "两次输入的恢复密钥不一致",
    );
    dict.set("common.retry", "重试");
    dict.set("common.close", "关闭");
    dict.set("common.cancel", "取消");
    dict.set("common.save", "保存");
    dict.set("common.edit", "编辑");
    dict.set("common.refresh", "刷新");
    dict.set("common.online", "在线");
    dict.set("common.offline", "离线");
    dict.set("qr_share.scan", "扫描二维码");
    dict.set("qr_share.unavailable", "二维码不可用");
    dict.set("qr_share.use_link", "或使用此链接");
    dict.set("qr_share.copy_link", "复制链接");
    dict.set("qr_share.copied", "已复制");
    dict.set(
        "qr_share.private_hint",
        "请勿公开此链接。链接会自动过期；配对链接被接受后也会立即失效。",
    );
    dict.set("message.actions", "消息操作");

    // R-i18n-002 mirrored keys.
    dict.set("topbar.search_placeholder", "跳转到 Realm、视图或操作...");
    dict.set("topbar.account_menu", "账号菜单");

    dict.set("login.continue", "继续");
    dict.set("login.working", "处理中...");
    dict.set("login.title", "登录");
    dict.set("login.completing", "正在完成登录");
    dict.set("login.station", "登录服务器");
    dict.set("login.station_url", "登录服务器地址");
    dict.set("login.show_preset_servers", "显示预设服务器");
    dict.set("login.preset_servers", "预设服务器");
    dict.set("login.status.signed_out", "未登录");
    dict.set("login.status.session_expired", "会话已过期");
    dict.set("login.status.signed_in", "已登录");
    dict.set("register.opening", "正在打开账户服务…");
    dict.set("register.error.technical_details", "技术详情");
    dict.set("register.error.invalid_server.title", "服务器地址无效");
    dict.set(
        "register.error.invalid_server.guidance",
        "请检查地址后重试。",
    );
    dict.set("register.error.unavailable.title", "账户服务暂时不可用");
    dict.set("register.error.unavailable.guidance", "请稍后重试。");
    dict.set("register.error.unexpected.title", "无法继续");
    dict.set(
        "register.error.unexpected.guidance",
        "请重试。如果问题持续，请展开下方技术详情。",
    );
    dict.set("login.refresh_now", "立即刷新");

    dict.set("dashboard.notifications_label", "通知");
    dict.set("dashboard.notifications_delta_unread", "未读与待审批");
    dict.set("dashboard.notifications_delta_signin", "需要登录");
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
        "Realm 级策略——在 Realm 设置中管理。",
    );
    dict.set("realm_admin.no_members_loaded", "还没有成员。");
    dict.set(
        "realm_admin.members_empty_hint",
        "用上方的 + 按钮邀请第一位成员。",
    );
    dict.set("realm_admin.members_no_match", "没有匹配的成员。");
    dict.set(
        "realm_admin.invite_hint",
        "最稳妥的方式是使用对方分享给你的邀请链接。如果对方允许被发现,也可以输入其用户名或身份地址,以及对方所在的服务器。",
    );

    // F-NOTIF-VLIST-1: pagination button copy synced with the en dict.
    dict.set("notifications.showing", "已显示");
    dict.set("notifications.load_more", "加载更多");
    dict.set("directory.loading_more", "加载中…");
    dict.set("directory.load_more_realms", "加载更多 Realm");
    dict.set("directory.load_more_organizations", "加载更多组织");
    dict.set("directory.load_more_actors", "加载更多成员");

    dict.set("command_palette.realms", "Realm");
    dict.set("command_palette.jump_to", "跳转到");
    dict.set(
        "command_palette.empty",
        "未找到匹配的 Realm 或视图。按 Esc 关闭。",
    );
    dict.set("command_palette.close", "关闭 (Esc)");

    dict.set("mobile.filter_realms", "筛选 Realm...");
    dict.set("mobile.no_match", "未找到匹配的 Realm。");

    // Kanban / Board view
    dict.set("kanban.board_header", "看板");
    dict.set("chat.send", "发送");
    dict.set("chat.send_secure", "加密发送");
    dict.set("chat.scheduled_send.send_at", "发送时间");
    dict.set("chat.scheduled_send.create", "定时发送");
    dict.set(
        "chat.scheduled_send.needs_body",
        "请先输入消息并选择发送时间",
    );
    dict.set("chat.scheduled_send.empty", "此讨论暂无定时消息。");
    dict.set("chat.scheduled_send.created", "已创建定时消息。");
    dict.set("chat.scheduled_send.updated", "定时消息已更新。");
    dict.set("chat.scheduled_send.cancelled", "定时消息已取消。");
    dict.set("chat.scheduled_send.edit", "修改");
    dict.set("chat.scheduled_send.save", "保存");
    dict.set("chat.scheduled_send.dismiss_edit", "取消");
    dict.set("chat.scheduled_send.cancel_plan", "删除");
    dict.set("realm_admin.save_profile", "保存资料");
    dict.set("realm_admin.destroy_realm", "销毁 Realm");
    dict.set("realm_admin.archive_realm", "归档 Realm");
    dict.set("kanban.add_card", "添加卡片");
    dict.set("kanban.add_list", "添加列表");
    dict.set("kanban.save_card", "保存");
    dict.set("kanban.cancel_card", "取消");
    dict.set("kanban.rename_list_hint", "双击重命名");
    dict.set("realm_admin.apply_policy", "应用策略");
    dict.set("realm_admin.grant_capability_move", "授予权限（Move）");
    dict.set("realm_admin.revoke_capability_move", "撤销权限（Move）");
    dict.set("realm_admin.admin_grant_title", "Realm 管理员");
    dict.set(
        "realm_admin.admin_grant_hint",
        "授予或撤销此 Realm 的管理员权限。更改经签名后提交,服务器处理完成后生效。",
    );
    dict.set("realm_admin.admin_subject_label", "管理员主体 ID");
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
    dict.set("realm_admin.leave_realm", "退出");
    dict.set("realm_admin.leave_confirm_title", "退出此 Realm？");
    dict.set(
        "realm_admin.leave_confirm_body",
        "离开后需要重新受邀才能回到此 Realm，本设备上的本地缓存也会被清除。",
    );
    dict.set("realm_admin.leave_confirm_target", "将退出的 Realm");
    dict.set("realm_admin.leave_confirm_button", "退出 Realm");
    dict.set("realm_admin.leave_confirm_cancel", "取消");
    dict.set("directory.list_contacts", "列出");
    dict.set("directory.search_button", "搜索");
    dict.set("directory.resolve_selected", "解析选中");
    dict.set("settings.register_push", "注册推送");
    dict.set("settings.unregister_push", "注销推送");
    // Settings navigation - section labels (design/settings-ia-reorg.md 3.1).
    dict.set("settings.section.account", "账号信息");
    dict.set("settings.section.agents", "我的智能体");
    dict.set("settings.section.server", "服务器信息");
    dict.set("settings.section.devices", "设备");
    dict.set("settings.section.storage", "数据与同步");
    dict.set("settings.section.encryption", "安全");
    dict.set("settings.section.recovery", "恢复");
    dict.set("settings.section.mimi", "集成");
    dict.set("settings.section.notifications", "通知");
    dict.set("settings.section.privacy", "隐私与分享");
    dict.set("settings.section.invite_policy", "谁能邀请我");
    dict.set("settings.section.consent", "邀请与同意");
    dict.set("settings.section.blocklist", "屏蔽名单");
    dict.set("settings.section.capabilities", "应用授权");
    dict.set("settings.section.theme", "外观与语言");
    dict.set("settings.section.release", "发布状态");
    dict.set("settings.section.audit", "审计日志");
    dict.set("settings.section.developer", "开发者工具");
    dict.set("settings.account.identity", "账号身份");
    dict.set("settings.profile.display_name", "显示名称");
    dict.set("settings.profile.bio", "个人简介");
    dict.set("settings.profile.save", "保存资料");
    dict.set("settings.profile.saving", "正在保存资料…");
    dict.set("settings.profile.saved", "资料已保存");
    dict.set("settings.profile.save_failed", "资料保存失败");
    dict.set("settings.profile.display_name_required", "显示名称不能为空");
    dict.set("settings.profile.invalid_display_name", "显示名称无效");
    dict.set("settings.account.no_device_session", "没有已认证的设备会话");
    dict.set("settings.account.handles", "账号标识");
    dict.set("settings.account.current_device", "当前设备");
    dict.set("settings.account.copy_did", "复制 DID");
    dict.set("settings.account.copy_handles", "复制账号标识");
    dict.set("settings.account.copy_device_id", "复制设备 ID");
    dict.set("settings.invite_locator.title", "安全邀请链接");
    dict.set("settings.invite_locator.expiry", "15 分钟后过期");
    dict.set("settings.invite_locator.issuing", "正在生成安全邀请链接…");
    dict.set("settings.invite_locator.rotating", "正在刷新安全邀请链接…");
    dict.set("settings.invite_locator.unavailable", "安全邀请链接不可用");
    dict.set(
        "settings.invite_locator.refresh_failed",
        "刷新安全邀请链接失败",
    );
    dict.set("settings.invite_locator.qr_aria", "安全邀请链接二维码");
    dict.set("settings.invite_locator.url_aria", "安全邀请链接地址");
    dict.set("settings.invite_locator.sign_in", "登录后显示安全邀请链接");
    // Settings navigation - group labels + hints.
    dict.set("settings.group.account", "账号");
    dict.set("settings.group.account.hint", "身份、智能体与服务器。");
    dict.set("settings.group.security", "设备与安全");
    dict.set(
        "settings.group.security.hint",
        "已登录设备、恢复与应用授权。",
    );
    dict.set("settings.group.privacy", "隐私");
    dict.set("settings.group.privacy.hint", "个人私密的披露控制。");
    dict.set("settings.group.notifications", "通知");
    dict.set("settings.group.notifications.hint", "通知投递行为。");
    dict.set("settings.group.appearance", "外观与语言");
    dict.set("settings.group.appearance.hint", "主题与语言。");
    dict.set("settings.group.advanced", "高级");
    dict.set("settings.group.advanced.hint", "数据、连接与协议诊断。");
    // Settings-nav filter (design 3.4).
    dict.set("settings.search.placeholder", "搜索设置…");
    // T1.3 - event signature / proof mode status display.
    dict.set("settings.proof_mode.label", "事件签名");

    // Settings surfaces wired in the `views/settings/mod.rs` sweep:
    // server information, local stores, storage diagnostics, encryption,
    // MIMI interop, notifications, push, privacy/presence, read receipts,
    // remarks, handle, appearance and session diagnostics.
    dict.set("settings.server.context", "服务器上下文");
    dict.set("settings.server.station", "Station");
    dict.set("settings.server.session", "会话");
    dict.set("settings.server.session_authenticated", "已认证");
    dict.set("settings.server.push", "推送");
    dict.set("settings.avatar.account_alt", "账号头像");
    dict.set("settings.avatar.edit_dialog", "编辑头像");
    dict.set("settings.avatar.selected_alt", "已选头像");
    dict.set("settings.avatar.cleared_synced", "已从同步偏好中清除头像");
    dict.set("settings.avatar.restored_synced", "已从同步偏好中恢复头像");
    dict.set("settings.avatar.removing", "正在从公开资料中移除头像。");
    dict.set(
        "settings.avatar.removed",
        "头像已移除；正在向其他设备同步该清除。",
    );
    dict.set("settings.local_stores.title", "本地存储");
    dict.set("settings.local_stores.badge", "状态");
    dict.set("settings.local_stores.config_store", "配置存储");
    dict.set("settings.local_stores.state_store", "状态存储");
    dict.set("settings.local_stores.active", "运行中");
    dict.set("settings.local_stores.config_size", "配置大小");
    dict.set("settings.local_stores.approx_bytes", "约 {bytes} 字节");
    dict.set("settings.local_stores.platform", "平台");
    dict.set("settings.local_stores.platform_web", "Web（localStorage）");
    dict.set("settings.local_stores.platform_native", "原生（文件系统）");
    dict.set("settings.storage_risks.title", "存储诊断");
    dict.set(
        "settings.storage_risks.bounded_projection",
        "有界的 localStorage 投影 ",
    );
    dict.set(
        "settings.storage_risks.bounded_projection_hint",
        "localStorage 只承载很小的 root/config 投影。账号状态、E2EE 明文、会话凭据与密钥材料都放在受保护的 IndexedDB 层。",
    );
    dict.set("settings.storage_risks.badge_bounded", "有界");
    dict.set(
        "settings.storage_risks.protected_e2ee",
        "受保护的 E2EE 存储 ",
    );
    dict.set(
        "settings.storage_risks.protected_e2ee_hint",
        "E2EE 明文缓存与账号机密状态使用不可导出的 SubtleCrypto 包装密钥加密存放在 IndexedDB 中，且从不镜像到 localStorage。",
    );
    dict.set("settings.storage_risks.single_tab", "单个活动浏览器标签页 ");
    dict.set(
        "settings.storage_risks.single_tab_hint",
        "Inkson 每个浏览器配置只允许一个活动标签页，使 IndexedDB、设备密钥、MLS 状态、游标与出站写入只有一个所有者。",
    );
    dict.set("settings.storage_risks.badge_info", "提示");
    dict.set("settings.storage_risks.filesystem", "文件系统存储 ");
    dict.set(
        "settings.storage_risks.filesystem_hint",
        "使用原生文件系统存储，数据跨会话保留。请确保文件权限设置正确以保障安全。",
    );
    dict.set("settings.storage_risks.badge_ok", "正常");
    dict.set("settings.encryption.badge", "MLS / E2EE");
    dict.set(
        "settings.encryption.always_on",
        "加密 Realm 始终启用端到端加密。可在下方管理你的恢复密钥。",
    );
    dict.set("settings.key_backup.title", "高级密钥备份诊断");
    dict.set("settings.key_backup.badge", "开发者工具");
    dict.set(
        "settings.key_backup.body",
        "上方的加密历史恢复会自动创建密钥备份信封。恢复备份 id 在创建备份时生成，不需要手工输入。",
    );
    dict.set(
        "settings.key_backup.open_recovery_hint",
        "调试某个具体备份信封时请打开「恢复」页面。",
    );
    dict.set("settings.key_backup.open_recovery", "恢复与备份");
    dict.set(
        "settings.key_backup.contract",
        "契约：ak.schema.key_backup.v1，位于 /_arkret/self/keys/backups/*。加密历史恢复的设置不需要它。",
    );
    dict.set("settings.mimi.title", "MIMI 互操作检查");
    dict.set("settings.mimi.refresh_directory", "刷新目录");
    dict.set("settings.mimi.identifier_query", "标识符查询");
    dict.set("settings.mimi.submit_message", "提交测试消息");
    dict.set("settings.mimi.proxy_download", "代理下载");
    dict.set("settings.mimi.directory_badge", "能力");
    dict.set("settings.mimi.receipt_title", "回执");
    dict.set("settings.mimi.receipt_badge", "最近一次操作");
    dict.set("settings.mimi.not_loaded", "尚未加载");
    dict.set("settings.mimi.no_receipt", "暂无 MIMI 操作回执");
    dict.set("settings.notifications.defaults_title", "全局通知默认值");
    dict.set("settings.notifications.defaults_badge", "已同步");
    dict.set(
        "settings.notifications.defaults_body",
        "除非你在下方添加按 Realm 的覆盖，否则对所有 Realm 生效。",
    );
    dict.set("settings.notifications.sound_on", " 声音提醒");
    dict.set("settings.notifications.sound_off", " 声音提醒已关闭");
    dict.set("settings.notifications.sound_enabled", "声音提醒已开启。");
    dict.set("settings.notifications.sound_disabled", "声音提醒已关闭。");
    dict.set("settings.notifications.sound_test", "测试声音");
    dict.set(
        "settings.notifications.sound_test_played",
        "已播放声音提醒测试。",
    );
    dict.set(
        "settings.notifications.sound_test_blocked",
        "请先开启声音提醒再测试。",
    );
    dict.set("settings.notifications.dnd", " 免打扰");
    dict.set("settings.notifications.dnd_off", "关闭");
    dict.set("settings.notifications.dnd_now", "现在");
    dict.set("settings.notifications.overrides_title", "按 Realm 覆盖");
    dict.set(
        "settings.notifications.overrides_body",
        "选择一个 Realm 及其通知程度。这只会为该 Realm 覆盖上方的全局默认值。",
    );
    dict.set("settings.notifications.no_realms", "暂无可选的 Realm");
    dict.set("settings.notifications.select_realm", "选择一个 Realm…");
    dict.set("settings.notifications.notify_label", "通知我");
    dict.set("settings.notifications.level_all", "所有消息");
    dict.set("settings.notifications.add_override", "添加覆盖");
    dict.set(
        "settings.notifications.overrides_empty",
        "还没有按 Realm 的覆盖。未配置的 Realm 沿用全局默认值。",
    );
    dict.set("settings.notifications.clear_overrides", "清除所有覆盖");
    dict.set("settings.push.title", "推送投递");
    dict.set("settings.push.badge", "配置");
    dict.set("settings.push.body", "推送通知偏好与网关注册。");
    dict.set("settings.push.current", "当前：{state}");
    dict.set("settings.push.not_registered", "未注册");
    dict.set("settings.privacy.badge", "可见性控制");
    dict.set("settings.privacy.presence_visibility", "在线状态可见性");
    dict.set(
        "settings.privacy.presence_visibility.public",
        "共同 Realm 中的所有人",
    );
    dict.set(
        "settings.privacy.presence_visibility.contacts_only",
        "仅联系人",
    );
    dict.set(
        "settings.privacy.presence_visibility.nobody",
        "任何人都不可见（显示为离线）",
    );
    dict.set("settings.privacy.status_title", "我的状态");
    dict.set("settings.privacy.status_badge", "手动在线状态");
    dict.set("settings.privacy.presence_state.auto", "自动");
    dict.set("settings.privacy.presence_state.online", "在线");
    dict.set("settings.privacy.presence_state.idle", "空闲");
    dict.set("settings.privacy.presence_state.dnd", "免打扰（忙碌）");
    dict.set(
        "settings.privacy.status_message_placeholder",
        "状态消息（例如：会议中）",
    );
    dict.set("settings.privacy.status_expiry.never", "不自动清除");
    dict.set("settings.privacy.status_expiry.30m", "30 分钟后清除");
    dict.set("settings.privacy.status_expiry.1h", "1 小时后清除");
    dict.set("settings.privacy.status_expiry.today", "今天结束时清除");
    dict.set("settings.privacy.status_save", "保存状态");
    dict.set("settings.privacy.status_clear", "清除");
    dict.set("settings.privacy.status_invalid", "状态消息无效：{error}");
    dict.set(
        "settings.privacy.status_state_unknown",
        "状态取值不在协议的封闭集合内。",
    );
    dict.set("settings.privacy.status_cleared", "状态已清除。");
    dict.set("settings.privacy.status_saved", "状态已保存。");
    dict.set("settings.read_receipts.default_badge", "默认");
    dict.set("settings.read_receipts.send_default", " 默认发送已读回执");
    dict.set(
        "settings.read_receipts.display_default",
        " 默认显示他人的已读回执",
    );
    dict.set("settings.read_receipts.realm_exceptions", "Realm 例外");
    dict.set("settings.read_receipts.badge_sending", "发送中");
    dict.set("settings.read_receipts.badge_skipping", "已跳过");
    dict.set("settings.read_receipts.locked", "已被 Realm 策略锁定");
    dict.set("settings.read_receipts.switch_to_skip", "改为跳过");
    dict.set("settings.read_receipts.switch_to_send", "改为发送");
    dict.set("settings.read_receipts.inherit_default", "继承默认值");
    dict.set("settings.read_receipts.add_skip", "添加（跳过）");
    dict.set("settings.read_receipts.add_send", "添加（发送）");
    dict.set("settings.remarks.badge_private", "私有");
    dict.set("settings.realm_remarks.title", "Realm 备注");
    dict.set(
        "settings.realm_remarks.empty",
        "还没有备注。可在下方添加，用来区分同名的 Realm。",
    );
    dict.set(
        "settings.realm_remarks.local_name_private",
        "本地名称（私有）",
    );
    dict.set("settings.realm_remarks.local_name", "本地名称");
    dict.set("settings.realm_remarks.add", "添加备注");
    dict.set("settings.contact_petnames.title", "联系人昵称");
    dict.set(
        "settings.contact_petnames.body",
        "昵称在所有 Realm 中是全局的。请在已接受的真人联系人行中添加或编辑；任意 DID 与 Realm 成员不能设置昵称。",
    );
    dict.set("settings.contact_petnames.empty", "尚未保存联系人昵称。");
    dict.set("settings.handle.title", "Handle");
    dict.set("settings.handle.managed_badge", "由你的组织管理");
    dict.set(
        "settings.handle.managed_body",
        "你的 handle 由所属组织管理。本客户端不能直接设置或修改，请通过组织的签发方申请变更。",
    );
    dict.set("settings.handle.issuer_link", "在组织的签发方管理 handle");
    dict.set(
        "settings.handle.issuer_link_unavailable",
        "签发方链接不可用",
    );
    dict.set("settings.theme.badge", "外观");
    dict.set("settings.theme.light", "浅色主题");
    dict.set("settings.theme.night", "深色主题");
    dict.set("settings.theme.system", "跟随系统");
    dict.set("settings.theme.current", "当前：{theme}");
    dict.set("settings.language.title", "语言");
    dict.set("settings.session_diagnostics.title", "会话诊断");
    dict.set("settings.proof_mode.real_ed25519", "真实 Ed25519");
    dict.set("settings.proof_mode.external_signer", "外部 signer");
    dict.set(
        "settings.proof_mode.production",
        "未配置 signer（生产模式）",
    );

    // T5.2 — signer DID / key id / freshness panel
    dict.set("settings.signer.label", "活跃签名者");
    dict.set("kanban.archive_action", "归档");
    dict.set("kanban.card.draft", "草稿");
    dict.set(
        "kanban.card.draft_hint",
        "已在本地排队;正在等待服务器确认该卡片。",
    );
    dict.set(
        "kanban.archive_draft_blocked",
        "该卡片仍是本地草稿;请等待同步完成后再归档。",
    );
    dict.set("kanban.archive_board_action", "归档看板");
    dict.set("kanban.archive_board_pending", "正在归档看板及其全部卡片…");
    dict.set("kanban.archive_board_done", "看板已归档;卡片已级联归档。");
    dict.set("kanban.archive_board_confirm_title", "归档此看板？");
    dict.set(
        "kanban.archive_board_confirm_scope",
        "这将归档该看板及其 {lists} 个活动列表和 {cards} 张活动卡片。",
    );
    dict.set(
        "kanban.archive_board_confirm_recover",
        "已归档的列表和卡片之后可从「已归档」区恢复。",
    );
    dict.set("kanban.archive_board_confirm_confirm", "归档看板");
    dict.set("kanban.archive_board_confirm_cancel", "取消");
    dict.set("kanban.archive_list_confirm_title", "归档此列表？");
    dict.set(
        "kanban.archive_list_confirm_body",
        "归档「{title}」后，该列表及其 {cards} 张活动卡片将从看板中隐藏，可从「已归档列表」区恢复。",
    );
    dict.set("kanban.archive_list_confirm_confirm", "归档列表");
    dict.set("kanban.archive_list_confirm_cancel", "取消");
    dict.set("kanban.restore_action", "恢复");
    dict.set("error.circle.realm_mismatch", "Circle 不属于该 Realm。");
    dict.set(
        "error.circle.not_active",
        "Circle 已归档或已终止，不能继续写入。",
    );
    dict.set(
        "error.circle.not_archived",
        "只有已归档的 Circle 可以恢复。",
    );
    dict.set(
        "error.circle.member_not_in_realm",
        "该用户不是父 Realm 的成员，不能加入 Circle。",
    );
    dict.set(
        "error.circle.scope_rebind_forbidden",
        "改变已有对象的 Circle scope 需要审计管理操作。",
    );
    dict.set(
        "error.circle.metadata_floor",
        "这次写入会低于 Realm 或 Circle 的元数据加密下限。",
    );
    dict.set(
        "error.circle.encryption_below_realm_floor",
        "该 Realm 要求 E2EE，Circle 必须保持 MLS 加密。",
    );
    // CircleScopePicker 的默认 scope 选项与帮助文案。
    dict.set("circle.scope.realm_everyone", "Realm（所有人）");
    dict.set(
        "circle.scope.help",
        "选择 Circle 可将可见范围限制为 Realm 成员的严格子集。",
    );
    dict.set("kanban.archived_lists_header", "已归档列表");
    dict.set("kanban.archived_lists_empty", "暂无已归档列表。");
    dict.set("kanban.archived_cards_header", "已归档卡片");
    dict.set("kanban.archived_cards_empty", "暂无已归档卡片。");
    // Directory view
    dict.set("directory.org_empty_body", "未找到组织，可尝试搜索。");
    dict.set("directory.actors_empty_body", "未找到 actor，可尝试搜索。");

    // Recovery view
    dict.set("recovery.recovery_key_section", "恢复密钥（24 词）");

    // 确认离线保存后的恢复密钥上传状态（`views/recovery/upload.rs`）。
    dict.set(
        "recovery.upload.publishing",
        "恢复密钥已确认——正在发布恢复策略和加密备份…",
    );
    dict.set(
        "recovery.upload.backed_up",
        "恢复密钥已创建，恢复策略和加密的账户备份已保存。请把 24 个词写下来——这是在新设备上恢复的唯一方式。",
    );
    dict.set(
        "recovery.upload.device_unauthorized",
        "此设备无权设置账户恢复密钥。请从你已在使用的设备上授权，或使用现有的 24 词恢复密钥进行恢复。",
    );
    dict.set(
        "recovery.upload.unreachable",
        "无法连接服务器以设置恢复(未做任何更改):{error}。请重试。",
    );

    // Recovery panel (`views/recovery/panel.rs`) — headers, buttons,
    // status lines, and backup-history copy.
    dict.set("recovery.panel.aria_label", "恢复与密钥备份");
    dict.set("recovery.panel.options", "恢复选项");
    dict.set(
        "recovery.panel.overview_help",
        "恢复密钥（24 个词）是唯一的恢复凭证。Arkret 不会在服务器上保存它；备份在上传前就在本设备完成加密。新设备只有在你的恢复策略接受其证明后才会获得授权。",
    );
    dict.set(
        "recovery.panel.status.publishing",
        "正在发布已确认的恢复密钥…",
    );
    dict.set("recovery.panel.status.write_down", "现在就写下这些词");
    dict.set("recovery.panel.status.accepted", "恢复密钥已确认 ✓");
    dict.set(
        "recovery.panel.status.unconfirmed",
        "服务器上已有备份——本设备尚未确认",
    );
    dict.set("recovery.panel.status.not_set", "未设置 ⚠");
    dict.set(
        "recovery.panel.detail.publishing",
        "离线副本已确认，正在保存恢复策略和第一份加密备份。",
    );
    dict.set(
        "recovery.panel.detail.custody",
        "先写下这些词，然后重新输入，之后才会发布任何内容。",
    );
    dict.set(
        "recovery.panel.detail.confirmed",
        "恢复密钥已在此设备上确认",
    );
    dict.set("recovery.panel.detail.accepted_at", "确认于 {when}");
    dict.set(
        "recovery.panel.detail.material_elsewhere",
        "已存在确认的恢复密钥，但本设备不保存这些词。",
    );
    dict.set(
        "recovery.panel.detail.generate_cta",
        "生成一个以启用跨设备恢复",
    );
    dict.set("recovery.panel.protects_title", "保护内容");
    dict.set("recovery.panel.protects_value", "加密历史");
    dict.set(
        "recovery.panel.protects_hint",
        "你的加密密钥和自己的内容，自动备份",
    );
    dict.set("recovery.panel.keep_offline", "离线保存");
    dict.set("recovery.panel.badge_not_backed_up", "尚未备份");
    dict.set("recovery.panel.badge_backed_up", "已备份");
    dict.set(
        "recovery.panel.key_help",
        "这是账号唯一的恢复凭证。生成后，这 24 个词会保护你的加密密钥并上传一份加密备份；此后你自己的内容会自动备份。这些词永远不会离开本设备（本地只保存指纹）,Arkret 无法替你找回，请务必写下来。丢失它们意味着加密历史无法恢复。",
    );
    dict.set(
        "recovery.panel.publishing_title",
        "正在发布恢复策略和加密备份…",
    );
    dict.set(
        "recovery.panel.publishing_hint",
        "在写入成功或你重试之前，确认的词只保留在内存中。",
    );
    dict.set("recovery.panel.not_generated", "尚未生成");
    dict.set(
        "recovery.panel.not_generated_hint",
        "生成一个，新设备才能解开你的加密备份。",
    );
    dict.set(
        "recovery.panel.write_down_title",
        "现在就把这 24 个词写下来。",
    );
    dict.set(
        "recovery.panel.write_down_body",
        "从屏幕上清除之前，请在下方重新输入保存的词。",
    );
    dict.set("recovery.panel.confirm_label", "重新输入保存的恢复密钥");
    dict.set(
        "recovery.panel.confirm_placeholder",
        "输入或粘贴你保存的 24 个词",
    );
    dict.set(
        "recovery.panel.confirm_hint",
        "明文被清除前，词必须完全匹配。如果某个词错了，检查会告诉你要修正的位置——无需重新生成。",
    );
    dict.set(
        "recovery.panel.plaintext_cleared",
        "这些词已不在内存中。更换恢复密钥需要走分阶段交接流程。",
    );
    dict.set("recovery.panel.rotation_guard_title", "已禁用直接更换。");
    dict.set(
        "recovery.panel.rotation_guard_body",
        "新的恢复密钥必须通过两步交接流程激活，所有受保护的备份都要重新加密后，旧密钥才会被吊销。",
    );
    dict.set("recovery.panel.last_accepted", "最近确认");
    dict.set("recovery.panel.rotate_hint", "只能通过分阶段交接流程更换");
    dict.set("recovery.panel.fingerprint", "指纹");
    dict.set("recovery.panel.fingerprint_hint", "仅保存在本地，从不上传");
    dict.set(
        "recovery.panel.goto_devices_title",
        "先在你已使用的设备上授权此设备，然后回来生成密钥。",
    );
    dict.set("recovery.panel.goto_devices", "打开设备设置");
    dict.set(
        "recovery.panel.regenerate_title_fresh",
        "丢弃当前显示的词并准备新的恢复密钥。",
    );
    dict.set(
        "recovery.panel.regenerate_title_guard",
        "直接更换不安全，请使用分阶段交接。",
    );
    dict.set(
        "recovery.panel.regenerate_title_default",
        "在本地生成这些词；重新输入之前不会发布任何内容。",
    );
    dict.set("recovery.panel.generate_failed", "生成失败:{error}");
    dict.set(
        "recovery.panel.generated_status",
        "把词离线写下来并重新输入。尚未发布任何恢复密钥。",
    );
    dict.set("recovery.panel.publishing_button", "发布中…");
    dict.set("recovery.panel.start_over", "改用新密钥重新开始");
    dict.set("recovery.panel.generate", "生成");
    dict.set("recovery.panel.handoff_required", "需要分阶段交接");
    dict.set(
        "recovery.panel.copy_title",
        "把 24 词恢复密钥复制到剪贴板。",
    );
    dict.set("recovery.panel.copied", "✓ 已复制！");
    dict.set("recovery.panel.copy", "复制");
    dict.set("recovery.panel.retry_title", "清空输入并重新输入保存的词。");
    dict.set("recovery.panel.retry", "清除并重试");
    dict.set(
        "recovery.panel.clear_live_title",
        "发布恢复密钥前，请先确认离线副本。",
    );
    dict.set(
        "recovery.panel.custody_confirmed",
        "离线副本已确认。正在发布恢复策略和第一份加密备份…",
    );
    dict.set(
        "recovery.panel.metadata_save_failed",
        "恢复密钥已被接受，但保存本地元数据失败。",
    );
    dict.set(
        "recovery.panel.accepted_done",
        "恢复密钥已确认；这些词已从内存清除。请妥善保管离线副本。",
    );
    dict.set(
        "recovery.panel.retry_extra",
        " 如果保存的副本一直校验失败，请改用新密钥重新开始。",
    );
    dict.set(
        "recovery.panel.word_count",
        "你输入了 24 个词中的 {entered} 个。请补全后再次确认。{extra}",
    );
    dict.set(
        "recovery.panel.word_mismatch",
        "第 {index} 个词与显示的密钥不一致。修正后再次确认。{extra}",
    );
    dict.set("recovery.panel.confirm_publish", "确认保管并发布");
    dict.set("recovery.panel.history_title", "高级 · 备份历史");
    dict.set("recovery.panel.history_subtitle", "仅服务器端加密副本");
    dict.set(
        "recovery.panel.history_help",
        "显示服务器上加密备份的创建时间。备份内容保持加密，不会在此显示。",
    );
    dict.set("recovery.panel.fetching", "正在获取备份时间…");
    dict.set("recovery.panel.fetch_failed", "备份时间:{error}");
    dict.set("recovery.panel.loading", "加载中…");
    dict.set("recovery.panel.next_page", "下一页");
    dict.set(
        "recovery.panel.partial_page",
        "当前仅显示这一页备份，后面还有更多。清空列表后可从第一页重新读取。",
    );
    dict.set("recovery.panel.refresh", "刷新备份时间");
    dict.set(
        "recovery.panel.clear_title",
        "只清除本地面板，不会删除服务器备份。",
    );
    dict.set(
        "recovery.panel.cleared",
        "已清除本地备份历史。服务器备份未被删除。",
    );
    dict.set("recovery.panel.clear", "清除面板");
    dict.set(
        "recovery.panel.no_backups",
        "未找到服务器上的加密备份。恢复策略状态会单独检查。",
    );
    dict.set("recovery.panel.not_loaded", "尚未加载备份时间。");
    dict.set(
        "recovery.panel.inventory_empty",
        "已从服务器加载 0 条备份时间。恢复策略状态与加密备份清单分开检查。",
    );
    dict.set(
        "recovery.panel.inventory_loaded",
        "已加载 {count} 条备份时间。最近备份:{latest}",
    );
    dict.set("recovery.panel.last_backup", "最近备份");
    dict.set("recovery.panel.backups_found", "发现的备份");
    dict.set("recovery.panel.snapshots", "加密快照");
    dict.set("recovery.panel.backup_times", "备份时间");
    dict.set("recovery.panel.total", "共 {total} 条");
    dict.set("recovery.panel.latest", "最新");
    dict.set(
        "recovery.panel.older_hidden",
        "另有 {count} 条较早的备份时间被隐藏",
    );
    dict.set(
        "recovery.panel.writeback_title",
        "高级 · 恢复成功后会发生什么",
    );
    dict.set("recovery.panel.writeback_subtitle", "按恢复方式留证");
    dict.set(
        "recovery.panel.writeback_body",
        "完整的恢复会让新设备生成自己的密钥、向当前恢复策略出示证明、记录恢复回执、完成自身授权，然后解开你的加密历史备份。备份历史仍显示在上方；策略证明和设备授权是后续的独立步骤。",
    );
    dict.set("device_authorization.title", "授权此设备");
    dict.set(
        "device_authorization.subtitle",
        "请在另一台已授权设备上确认",
    );
    dict.set(
        "device_authorization.description",
        "此浏览器已登录,但尚未被信任来处理加密数据。请在此发起授权请求——你已信任的设备通常会自动弹出确认提示。",
    );
    dict.set(
        "device_authorization.approve_step_existing_title",
        "在已有设备上",
    );
    dict.set(
        "device_authorization.approve_step_existing_body",
        "在确认提示中比对 8 位验证码，然后批准。如果没有弹出提示，请打开“设置 → 设备 → 添加设备”并刷新待审批请求。",
    );
    dict.set(
        "device_authorization.approve_step_new_title",
        "在此浏览器上",
    );
    dict.set(
        "device_authorization.approve_step_new_body",
        "保持审批请求页面打开。在另一台设备批准后，回到这里检查状态。",
    );
    dict.set(
        "device_authorization.limitation",
        "批准前，加密历史和安全敏感操作仍不可用。你可以先以受限模式继续，并随时回来完成此步骤。",
    );
    dict.set("device_authorization.open_pairing", "开始设备审批");
    dict.set("device_authorization.dismiss", "以受限模式继续");
    dict.set("device_authorization.reopen", "授权此设备");
    dict.set("mls_unlock.title", "恢复加密密钥");
    dict.set("mls_unlock.subtitle", "设备授权与密钥恢复是两个独立步骤");
    dict.set(
        "mls_unlock.description",
        "此设备已获授权，但账户加密密钥或历史材料仍待恢复。批准设备本身不会恢复这些秘密。",
    );
    dict.set("mls_unlock.approve_step_existing_title", "设备审批已完成");
    dict.set(
        "mls_unlock.approve_step_existing_body",
        "请勿为此设备重复创建配对请求。批准允许登录，但不能替代账户密钥恢复或 MLS 入群。",
    );
    dict.set("mls_unlock.approve_step_new_title", "在此浏览器上");
    dict.set("mls_unlock.approve_step_new_body", "在下方使用恢复密钥恢复既有账户密钥。发送新的加密内容还需要此设备已接受的 MLS 成员资格和持久化的本地状态。");
    dict.set(
        "mls_unlock.loading_hint",
        "批量恢复加密 Realm 可能需要几秒钟，请保持此标签页打开。",
    );
    dict.set("mls_unlock.limitation", "你可以稍后恢复。如果缺少账户加密 root，新加密内容和 MLS 初始化也会受阻，不只是旧历史不可读。");
    dict.set("mls_unlock.show_recovery_key", "改用恢复密钥");
    dict.set("mls_unlock.hide_recovery_key", "隐藏恢复密钥");
    dict.set("mls_unlock.recovery_fallback_hint", "24 词恢复密钥在校验通过后解锁既有账户加密备份；它不会克隆另一台设备，也不能跳过 MLS 入群。");
    dict.set("mls_unlock.placeholder", "24 词恢复密钥");
    dict.set("mls_unlock.button_idle", "用密钥解锁");
    dict.set("mls_unlock.button_busy", "正在解锁…");
    dict.set("mls_unlock.dismiss", "稍后恢复");
    dict.set("mls_unlock.reopen", "恢复加密密钥");
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
        "此 Realm 采用端到端加密,这台设备还没有打开它的密钥。如果你刚加入,密钥会自动送达——刷新页面或等待同步完成;你加入之前的消息在任何设备上都无法打开。要恢复自己旧设备上的内容,请到 设置 → 恢复 设置恢复密钥。",
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
        "24 个恢复词出现后请立即保存。Arkret 不会保存它们；遗失后，已设置好的设备仍可继续使用，但新设备无法恢复这份加密历史。",
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
    dict.set(
        "settings.mls_keypackages.refill_description",
        "若邀请无法送达此设备，可手动发布一批有界的新 MLS KeyPackage。",
    );
    dict.set(
        "settings.mls_keypackages.refill_button",
        "检查并补充 KeyPackage",
    );
    dict.set(
        "settings.mls_keypackages.refill_busy",
        "正在检查本地 MLS KeyPackage 库存…",
    );
    dict.set(
        "settings.mls_keypackages.refill_done",
        "KeyPackage 维护完成，本次发布：",
    );
    dict.set(
        "settings.mls_keypackages.refill_failed",
        "MLS KeyPackage 补充失败：",
    );

    // Space-admin view
    dict.set("realm_admin.members", "成员");
    dict.set("realm_admin.access", "访问控制");

    // Chat / Discussion view
    dict.set("chat.discussions_header", "Strand 讨论");
    dict.set("chat.users_header", "用户");
    dict.set("chat.settings_header", "设置");
    dict.set("chat.new_strand", "新建 Strand");
    dict.set("chat.hide_list", "隐藏讨论列表");
    dict.set("chat.label.title", "标题");
    dict.set("chat.label.summary", "概述");
    dict.set("chat.call.voice", "发起语音通话");
    dict.set("chat.call.video", "发起视频通话");
    // T7.2 watch-level quick switch
    dict.set("chat.watch_level.tooltip", "选择此 Strand 的通知频率。");
    dict.set("chat.watch_level.prefix", "通知");
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
    dict.set("chat.binding_context.details", "显示服务绑定");
    // T7.4 E2EE state
    dict.set("chat.crypto.decrypting", "解密中…");
    dict.set("chat.crypto.key_missing", "尚未收到密钥");
    dict.set(
        "chat.crypto.key_missing_hint",
        "正在等待 Welcome 消息或已授权的历史密钥源响应。",
    );
    dict.set("chat.crypto.needs_verification", "正在验证发送方身份…");
    // T6: human-readable copy for late-recovery rejections; the raw
    // protocol reason code is only surfaced via the element tooltip.
    dict.set(
        "chat.crypto.late_recovery_rejected",
        "无法恢复这条消息——加密密钥在你加入前已轮换。",
    );
    dict.set(
        "chat.crypto.undecryptable_generic",
        "此设备无法解密这条消息。",
    );
    // T7.5 layout adjustments
    dict.set("chat.tabs.settings", "设置");
    dict.set("chat.tabs.members", "成员");
    dict.set("chat.button.create", "创建");
    dict.set("chat.button.reply", "回复");
    dict.set("moderation.report.action", "举报");
    dict.set("moderation.report.title", "举报消息");
    dict.set(
        "moderation.report.help",
        "请选择最符合问题的原因。签名后的举报将提交到该 Realm 的治理流程。",
    );
    dict.set("moderation.report.reason", "原因");
    dict.set("moderation.report.reason.spam", "垃圾信息");
    dict.set("moderation.report.reason.harassment", "骚扰");
    dict.set("moderation.report.reason.hate_speech", "仇恨言论");
    dict.set("moderation.report.reason.nsfw", "色情内容");
    dict.set("moderation.report.reason.illegal", "违法内容");
    dict.set("moderation.report.reason.misinformation", "虚假信息");
    dict.set("moderation.report.reason.other", "其他");
    dict.set(
        "moderation.report.description",
        "详细说明（选择其他时必填）",
    );
    dict.set(
        "moderation.report.other_required",
        "选择其他时请填写详细说明",
    );
    dict.set("moderation.report.submit", "提交举报");
    dict.set("moderation.report.submitting", "正在提交…");
    dict.set("moderation.report.submitted", "举报已提交");
    dict.set("moderation.report.failed", "举报失败");
    dict.set("chat.button.react", "回应");
    dict.set("chat.button.redact", "撤回");
    // Member visual identity (member.badge.*)
    dict.set("member.badge.agent", "智能体");
    // Composer drag-and-drop attachments (A6.2)
    dict.set(
        "compose.drop_zone.hint",
        "将文件拖放到此处以附加,或点击「附加」",
    );
    dict.set("compose.upload_progress", "上传中…");
    dict.set("compose.upload_error", "上传失败");
    // Message write-status revision counter (edit history).
    dict.set("chat.message.revised", "已修订");
    dict.set("chat.message.write_status", "这条消息已被编辑");
    dict.set("chat.message.private_sidecar.label", "私密 Sidecar");
    dict.set(
        "chat.message.private_sidecar.tooltip",
        "仅你和此 Sidecar 中符合条件的个人 Agent 可以看到这条消息。",
    );
    // Offline send outbox.
    dict.set(
        "chat.outbox.queued_offline",
        "离线 - 已排队,重新联网后自动发送。",
    );
    dict.set(
        "chat.outbox.offline_banner",
        "你已离线。消息已排队,重新联网后将自动发送。",
    );
    dict.set("chat.outbox.flushing", "已恢复联网 - 正在发送排队的消息…");
    // Message shared pin and holder-private saved item actions.
    dict.set("message.shared_pin", "共享钉选");
    dict.set("message.shared_unpin", "取消共享钉选");
    dict.set("message.shared_pin_pending", "正在共享钉选…");
    dict.set("message.shared_unpin_pending", "正在移除共享钉选…");
    dict.set("message.shared_pinned", "共享钉选已更新。");
    dict.set("message.shared_unpinned", "共享钉选已移除。");
    dict.set("message.private_save", "仅为我保存");
    dict.set("message.private_saved", "已为我保存");
    dict.set("pinned_bar.title", "共享钉选消息");
    dict.set("pinned_bar.scroll_to", "跳转到消息");
    // Actor-private Realm list pinning.
    dict.set("realm.pin", "置顶 Realm");
    dict.set("realm.unpin", "取消置顶 Realm");
    dict.set("realm.pinned", "已置顶 Realm");
    dict.set("realm.unpinned", "已取消置顶 Realm");
    dict.set("realm.add_member", "添加成员");
    dict.set("realm.settings", "设置");
    dict.set("realm.pin_failed", "Realm 置顶 account-data 写入失败");
    // Actor-private contact list pinning.
    dict.set("contact.pin", "置顶联系人");
    dict.set("contact.unpin", "取消置顶联系人");
    dict.set("contact.pinned", "已置顶联系人");
    dict.set("contact.unpinned", "已取消置顶联系人");
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
        "已加载的通知全部被归档、类型或 Realm 静音规则过滤掉了。",
    );
    // Default titles / actions per notification kind (keys resolved via tr()).
    dict.set("notifications.default_title.invite", "Realm 邀请");
    dict.set("notifications.default_title.reaction", "新表情回应");
    dict.set("notifications.default_title.mention", "有人提到了你");
    dict.set("notifications.default_title.assignment", "分配给你的任务");
    dict.set("notifications.default_title.schedule", "日程已更新");
    dict.set("notifications.default_title.message", "新消息");
    dict.set("notifications.default_action.accept", "接受");
    dict.set("notifications.default_action.view", "查看");
    // Watch-level suppression hints (T4.4).
    dict.set(
        "notifications.watch_hint.not_mentioned",
        "你不会收到这个讨论的通知 — 可修改关注级别",
    );
    dict.set(
        "notifications.watch_hint.not_participating",
        "你只会收到已参与话题的通知 — 可修改关注级别",
    );
    dict.set(
        "notifications.watch_hint.limited",
        "这个讨论的通知受关注级别限制",
    );
    // Dashboard projection collection labels (keys resolved via tr()).
    dict.set("dashboard.node_kind.realm", "Realm");
    dict.set("dashboard.node_kind.space", "Space");
    dict.set("dashboard.collection.realms_and_spaces", "Realm 与 Space");
    dict.set("dashboard.collection.spaces", "Space");
    dict.set("dashboard.collection.realms", "Realm");
    dict.set(
        "dashboard.collection.recent_realms_and_spaces",
        "最近的 Realm 与 Space",
    );
    dict.set("dashboard.collection.recent_spaces", "最近的 Space");
    dict.set("dashboard.collection.recent_realms", "最近的 Realm");
    dict.set(
        "dashboard.collection.browse_realm_or_space",
        "搜索或加入 Realm 或 Space",
    );
    dict.set("dashboard.collection.browse_space", "搜索或加入 Space");
    dict.set("dashboard.collection.browse_realm", "搜索或加入 Realm");
    dict.set(
        "dashboard.collection.signin_realms_and_spaces",
        "登录后加载 Realm 与 Space",
    );
    dict.set("dashboard.collection.signin_spaces", "登录后加载 Space");
    dict.set("dashboard.collection.signin_realms", "登录后加载 Realm");
    dict.set(
        "dashboard.collection.empty_realms_and_spaces",
        "没有已加载的 Realm 或 Space",
    );
    dict.set("dashboard.collection.empty_spaces", "没有已加载的 Space");
    dict.set("dashboard.collection.empty_realms", "没有已加载的 Realm");
    dict.set(
        "dashboard.collection.empty_help_realms_and_spaces",
        "已连接的服务器尚未返回 Realm 或 Space。",
    );
    dict.set(
        "dashboard.collection.empty_help_spaces",
        "已连接的服务器尚未返回 Space。",
    );
    dict.set(
        "dashboard.collection.empty_help_realms",
        "已连接的服务器尚未返回 Realm。",
    );

    // Verify Device
    dict.set("verify_device.title", "设备验证");
    dict.set("verify_device.choose_method", "选择方式");
    dict.set("verify_device.qr_code", "二维码");
    dict.set("verify_device.sas_emoji", "表情符号比对");
    dict.set("verify_device.qr_section", "二维码验证");
    dict.set("verify_device.qr_section_hint", "扫描或显示");
    dict.set("verify_device.sas_section", "表情符号验证");
    dict.set("verify_device.sas_section_hint", "表情对比");
    dict.set("verify_device.target_device_id", "目标设备 ID");
    dict.set("verify_device.target_device_placeholder", "要验证的设备 ID");
    dict.set("verify_device.generate_qr", "生成二维码");
    dict.set("verify_device.start_sas", "开始表情符号验证");
    dict.set("verify_device.short_auth_string", "比对码");
    // 表情符号比对照料——面向用户的文案不再出现 SAS / X25519 术语；
    // 面板没有“技术详情”折叠区，术语直接去掉而不是藏起来。
    dict.set("verify_device.key_exchange_title", "密钥交换");
    dict.set("verify_device.keypair_ready", "密钥已生成");
    dict.set("verify_device.keypair_missing", "未生成");
    dict.set(
        "verify_device.key_exchange_hint",
        "生成一个新的一次性密钥，把公开部分发送到你的另一台设备，并把那台设备的公钥粘贴到下方。两边都就绪后，下方的表情符号和数字会自动更新。",
    );
    dict.set("verify_device.generate_keypair", "生成我的密钥");
    dict.set(
        "verify_device.keypair_generated",
        "密钥已生成——点击发送，把公开部分分享给另一台设备。",
    );
    dict.set(
        "verify_device.keypair_generate_failed",
        "无法生成密钥:{error}",
    );
    dict.set("verify_device.send_public_key", "发送我的公钥");
    dict.set("verify_device.generate_first", "请先生成密钥。");
    dict.set("verify_device.target_required", "请先输入要验证的设备 ID。");
    dict.set(
        "verify_device.send_failed_signing",
        "发送失败——本设备的签名密钥不可用:{error}",
    );
    dict.set(
        "verify_device.send_failed_sign",
        "发送失败——无法为密钥消息签名:{error}",
    );
    dict.set("verify_device.send_failed", "发送失败:{error}");
    dict.set(
        "verify_device.public_key_sent",
        "公钥已发送，等待另一台设备的密钥。",
    );
    dict.set("verify_device.my_public_key", "我的公钥:{key}");
    dict.set("verify_device.peer_key_placeholder", "粘贴另一台设备的公钥");
    dict.set(
        "verify_device.peer_key_autofilled",
        "已自动收到另一台设备的公钥。",
    );
    dict.set(
        "verify_device.session_started",
        "验证会话已开始。在两边设备上生成并交换密钥后，即可看到真实的表情符号和数字。",
    );
    dict.set(
        "verify_device.compare_hint",
        "在两台设备上对比这些表情符号和数字——必须完全一致。",
    );
    dict.set(
        "verify_device.source_secure",
        "由两台设备间的安全密钥交换得出。",
    );
    dict.set(
        "verify_device.source_demo_invalid",
        "占位结果——另一台设备的密钥无效。",
    );
    dict.set(
        "verify_device.source_demo_waiting",
        "占位结果——等待另一台设备的密钥。",
    );
    dict.set(
        "verify_device.match_requires_keys",
        "需要两台设备的密钥——请先生成并发送你的密钥，然后等待另一台设备的密钥。",
    );
    dict.set(
        "verify_device.match_failed_signing",
        "确认失败——本设备的签名密钥不可用:{error}",
    );
    dict.set(
        "verify_device.match_failed_sign",
        "确认失败——无法为证明签名:{error}",
    );
    dict.set(
        "verify_device.matched",
        "{target} 的比对结果一致。确认信息已在本设备签名，授权将通过配对流程继续。",
    );
    dict.set(
        "verify_device.mismatch_aborted",
        "不一致——已中止。新设备不会被授权，也不会收到加密历史。",
    );
    dict.set("verify_device.they_match", "一致");
    dict.set("verify_device.they_dont_match", "不一致");
    dict.set("verify_device.after_confirm_title", "确认后会发生什么");
    dict.set(
        "verify_device.after_confirm_body",
        "比对只是确认你信任新设备的密钥。下面四个步骤会把这份信任记录到你的账户中，让设备成为长期成员并能读取加密历史。",
    );
    dict.set("verify_device.step_authorize", "授权设备");
    dict.set(
        "verify_device.step_authorize_hint",
        "把新设备的公钥加入已授权列表",
    );
    dict.set("verify_device.step_record", "记录接受");
    dict.set(
        "verify_device.step_record_hint",
        "账户的设备目录会记录这次授权",
    );
    dict.set("verify_device.step_rejoin", "重新加入加密群组");
    dict.set(
        "verify_device.step_rejoin_hint",
        "每个空间会更新加密设置以纳入新设备",
    );
    dict.set("verify_device.step_sync", "同步密钥存储");
    dict.set(
        "verify_device.step_sync_hint",
        "拉取加密的密钥备份，使历史消息可解密",
    );
    dict.set(
        "verify_device.after_confirm_note",
        "登录、设备授权和设备验证是三个独立步骤。跳过验证只会得到短期会话，无法解密历史消息。",
    );

    // A6.4 - keyboard shortcut help overlay.
    dict.set("shortcuts.title", "键盘快捷键");
    dict.set("shortcuts.list.help", "显示此快捷键面板");
    dict.set("shortcuts.list.dismiss", "关闭任何打开的对话框");
    dict.set("shortcuts.list.palette", "打开命令面板");
    dict.set("shortcuts.list.palette_mac", "打开命令面板 (macOS)");
    dict.set("shortcuts.list.send", "发送当前消息");
    dict.set("shortcuts.list.send_alias", "发送当前消息（备用键）");
    // 个人屏蔽名单：设置卡片中的所有可见文案均由词典提供；Select
    // 的 wire value 保持不翻译。
    dict.set("settings.privacy.blocklist.title", "个人屏蔽名单");
    dict.set(
        "settings.privacy.blocklist.description",
        "被屏蔽的对象不会再出现在你各设备的消息和通知中。屏蔽设置仅自己可见，不会改变其他成员看到的内容。",
    );
    dict.set("settings.privacy.blocklist.empty_title", "屏蔽名单为空");
    dict.set(
        "settings.privacy.blocklist.empty_body",
        "你还没有屏蔽任何对象。",
    );
    dict.set("settings.privacy.blocklist.kind.domain", "域名");
    dict.set("settings.privacy.blocklist.kind.actor", "用户或代理");
    dict.set(
        "settings.privacy.blocklist.applies_summary",
        "适用范围：{surfaces}",
    );
    dict.set(
        "settings.privacy.blocklist.expires_summary",
        "到期时间：{expires}",
    );
    dict.set(
        "settings.privacy.blocklist.reason_summary",
        "原因：{reason}",
    );
    dict.set("settings.privacy.blocklist.unblock", "取消屏蔽");
    dict.set(
        "settings.privacy.blocklist.status.unblocked",
        "已取消屏蔽 {target}",
    );
    dict.set("settings.privacy.blocklist.target_type", "对象类型");
    dict.set("settings.privacy.blocklist.target.actor", "目标账户或代理");
    dict.set("settings.privacy.blocklist.target.domain", "目标域名");
    dict.set(
        "settings.privacy.blocklist.invalid.actor",
        "请输入完整的账户或代理身份；账户身份必须包含所属 Station。",
    );
    dict.set(
        "settings.privacy.blocklist.invalid.domain",
        "请输入有效域名，例如 example.com。",
    );
    dict.set("settings.privacy.blocklist.applies_to", "适用范围");
    dict.set(
        "settings.privacy.blocklist.applies_required",
        "请至少选择一个屏蔽范围。",
    );
    dict.set("settings.privacy.blocklist.surface.messages", "消息");
    dict.set("settings.privacy.blocklist.surface.mentions", "提及");
    dict.set("settings.privacy.blocklist.surface.dm", "私信");
    dict.set("settings.privacy.blocklist.surface.calls", "通话");
    dict.set("settings.privacy.blocklist.surface.contacts", "联系人");
    dict.set("settings.privacy.blocklist.surface.applets", "应用");
    dict.set("settings.privacy.blocklist.surface.presence", "在线状态");
    dict.set("settings.privacy.blocklist.surface.notifications", "通知");
    dict.set("settings.privacy.blocklist.surface.directory", "目录");
    dict.set("settings.privacy.blocklist.reason_optional", "原因（可选）");
    dict.set("settings.privacy.blocklist.no_reason", "不填写原因");
    dict.set("settings.privacy.blocklist.expires", "到期时间");
    dict.set("settings.privacy.blocklist.expiry.never", "永久");
    dict.set("settings.privacy.blocklist.expiry.1d", "24 小时");
    dict.set("settings.privacy.blocklist.expiry.7d", "7 天");
    dict.set("settings.privacy.blocklist.expiry.30d", "30 天");
    dict.set("settings.privacy.blocklist.block", "屏蔽对象");
    dict.set("settings.privacy.blocklist.status.added", "已屏蔽 {target}");
    dict.set(
        "settings.privacy.blocklist.status.duplicate",
        "{target} 已在屏蔽名单中",
    );
    // A4b - avatar upload.
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
    dict.set("search.placeholder", "在所有 Realm 中搜索消息…");
    dict.set("search.results.empty", "输入查询以在所有 Realm 中搜索。");
    dict.set("search.results.loading", "搜索中…");
    dict.set("search.results.error", "搜索失败");
    dict.set("search.no_results", "未找到匹配项。");
    dict.set("shortcuts.list.search", "打开全局消息搜索");
    dict.set("member.block", "屏蔽此用户");
    dict.set("member.block_confirm.title", "屏蔽此用户？");
    dict.set(
        "member.block_confirm.body",
        "其消息将被占位符替代。您可随时在 设置 → 隐私 中取消屏蔽。",
    );
    dict.set("member.block_confirm.confirm", "屏蔽");
    dict.set("message.blocked_user", "[已屏蔽用户]");
    dict.set("message.show_anyway", "仍要查看");

    // A3 (round 28): rich content renderer strings.
    dict.set("content.code.copy", "复制");
    dict.set("content.image.broken", "图片不可用");
    dict.set("content.video.unsupported", "您的浏览器不支持内嵌视频。");
    dict.set("content.audio.unsupported", "您的浏览器不支持内嵌音频。");
    dict.set("content.attachment.download", "下载");

    // T7.1 - friendly product terminology for Chinese.
    dict.set("friendly.identifier.show_technical", "显示技术详情");
    dict.set("friendly.identifier.hide_technical", "隐藏技术详情");

    // Realm is the security boundary (members / policy / federation / E2EE);
    // Space is the container (navigation / boards / lists).
    dict.set("friendly.realm", "Realm");
    dict.set(
        "friendly.realm.description",
        "Realm 统一管理其内部内容的成员、规则、跨服务器共享与加密。",
    );
    dict.set("friendly.space", "空间");
    dict.set(
        "friendly.space.description",
        "空间用于在 Realm 内组织看板、列表与分区。",
    );

    dict.set("feature_gate.loading", "正在检查服务器能力");
    dict.set("feature_gate.loading_body", "正在等待服务器能力描述。");
    dict.set("feature_gate.missing", "缺少的操作或传输绑定：");
    dict.set("profile_gate.title", "此服务器暂不支持该功能");
    dict.set(
        "profile_gate.body",
        "当前服务器尚未提供该视图所需的能力。请尝试其他服务器或联系管理员。",
    );
    dict.set(
        "profile_gate.technical_detail",
        "在 /server/describe 公布匹配的 profile 要求之前,该界面的写入控件保持隐藏。",
    );
    dict.set("profile_gate.friendly.minimal_client", "基础客户端");
    dict.set("profile_gate.friendly.kanban_mvp", "看板");
    dict.set("profile_gate.friendly.chat_mvp", "讨论");
    dict.set("profile_gate.friendly.full_client", "完整客户端");
    dict.set("profile_gate.friendly.e2ee_client", "加密通讯");
    dict.set("profile_gate.friendly.unknown", "客户端功能");

    dict.set("developer.title", "开发者工具");
    dict.set("developer.subtitle", "协议诊断与审计");
    dict.set("developer.section.events", "原始事件日志");
    dict.set("developer.section.protocol_version", "协议版本");
    dict.set(
        "developer.hint",
        "以下信息面向开发者和运维人员。终端用户无需阅读。",
    );
    dict.set("developer.profile.required", "所需 Profile id");

    // R3 spec sync (b47ff6ec) — Chinese error toast translations.
    add_r3_error_keys_zh(&mut dict);
    add_generic_error_keys_zh(&mut dict);

    // Contacts / invite-receive policy / realm invite-from-contacts.
    add_contacts_keys_zh(&mut dict);

    // Unified feedback system (toast host + app banner), Wave 0.
    add_feedback_keys_zh(&mut dict);

    // 设置页面（领域向导 / 空间表单 / 总览）与面包屑路由标签，
    // 对应 [`super::en`] 的 `setup_strings` / `route_label_strings`。
    setup_strings(&mut dict);
    route_label_strings(&mut dict);
    prompt_copy_strings(&mut dict);

    dict
}

/// Chinese strings for the unified feedback surface — mirrors
/// [`super::en`]'s `add_feedback_keys`.
fn add_feedback_keys_zh(dict: &mut TranslationDict) {
    dict.set("feedback.policy_denied", "服务器的策略不允许此操作。");
    dict.set(
        "feedback.banner_offline",
        "当前处于离线状态,网络恢复后改动将自动同步。",
    );
    dict.set("feedback.toast_overflow", "还有 {count} 条");
    dict.set("feedback.copy_detail", "复制详情");
    dict.set("feedback.dismiss", "关闭");

    // Wave 1 — operation-feedback toasts (former global status writes).
    dict.set("feedback.account_not_connected", "账号未连接,请先登录");
    dict.set("feedback.contacts_load_failed", "联系人加载失败");
    dict.set("feedback.realm_leaving", "正在退出 Realm:{realm}");
    dict.set("feedback.realm_left", "已退出 Realm:{realm}");
    dict.set("feedback.realm_leave_failed", "退出 Realm 失败:{realm}");
    dict.set("feedback.contact_deleting", "正在删除联系人:{name}");
    dict.set("feedback.contact_deleted", "已删除联系人:{name}");
    dict.set("feedback.contact_delete_failed", "删除联系人失败:{name}");
    dict.set("feedback.direct_open_failed", "无法打开私聊会话");
    dict.set(
        "feedback.direct_temporarily_unavailable",
        "暂时无法验证会话创建所需的身份或授权，请稍后重试",
    );
    dict.set(
        "feedback.direct_awaiting_founder",
        "等待对方首次创建此会话后即可打开",
    );
    dict.set(
        "feedback.direct_creation_blocked",
        "当前授权或运行状态不允许创建此会话",
    );
    dict.set("feedback.directory_search_failed", "目录搜索失败");
    dict.set("feedback.directory_resolve_failed", "目录解析失败");
    dict.set("feedback.directory_load_more_failed", "加载更多结果失败");
    dict.set(
        "feedback.realm_resolved",
        "Realm 已解析(加入规则:{join_rule})",
    );
    dict.set("feedback.realm_create_failed", "Realm 创建失败");
    dict.set("feedback.copied_did", "已复制 DID");
    dict.set("feedback.copied_handles", "已复制 Handle");
    dict.set("feedback.copied_device_id", "已复制设备 ID");
    dict.set("feedback.avatar_updated", "头像已更新");
    dict.set("feedback.mimi_failed", "MIMI 请求失败");
    dict.set("feedback.notification_kind_enabled", "已启用:{label}");
    dict.set("feedback.notification_kind_muted", "已静音:{label}");
    dict.set(
        "feedback.override_pick_realm",
        "请先选择一个 Realm 再添加覆盖项",
    );
    dict.set("feedback.watch_level_set", "已将 {realm} 设为 {level}");
    dict.set("feedback.override_removed", "已移除 {realm} 的通知覆盖项");
    dict.set(
        "feedback.overrides_cleared",
        "已清除所有按 Realm 的通知覆盖项",
    );
    dict.set("feedback.push_registered", "推送已注册:{label}");
    dict.set("feedback.push_register_failed", "推送注册失败");
    dict.set("feedback.push_unregistered", "推送已注销");
    dict.set("feedback.push_unregister_failed", "推送注销失败");
    dict.set(
        "feedback.presence_visibility_set",
        "在线状态可见范围:{visibility}",
    );
    dict.set("feedback.read_receipt_default_send_on", "已读回执:默认发送");
    dict.set(
        "feedback.read_receipt_default_send_off",
        "已读回执:默认不发送",
    );
    dict.set(
        "feedback.read_receipt_default_display_on",
        "已读回执:在会话中显示",
    );
    dict.set(
        "feedback.read_receipt_default_display_off",
        "已读回执:在会话中隐藏",
    );
    dict.set(
        "feedback.read_receipt_override_send",
        "{realm} 的已读回执:发送",
    );
    dict.set(
        "feedback.read_receipt_override_skip",
        "{realm} 的已读回执:不发送",
    );
    dict.set(
        "feedback.read_receipt_override_inherit",
        "{realm} 的已读回执:跟随默认",
    );
    dict.set("feedback.enter_realm_id", "请先输入 Realm ID");
    dict.set(
        "feedback.realm_remark_saved",
        "Realm 备注已保存:{realm} \u{2192} {name}",
    );
    dict.set(
        "feedback.realm_remark_cleared",
        "已清除 {realm} 的 Realm 备注",
    );
    dict.set(
        "feedback.enter_realm_and_name",
        "请同时输入 Realm ID 和本地名称",
    );
    dict.set(
        "feedback.invalid_realm_id",
        "Realm ID 必须以 ak:realm: 开头",
    );
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

    dict.set("settings.section.contacts", "联系人权限");
    dict.set(
        "contacts.settings.empty",
        "联系人请求接受后，可在这里调整其权限。",
    );
    // ── ContactNewPanel ───────────────────────────────────────────────
    dict.set("contacts.new.title", "添加联系人");
    dict.set("contacts.new.subtitle", "需对方同意");
    dict.set(
        "contacts.new.intro",
        "输入对方的邀请链接、handle 或完整账号标识发送好友请求。默认允许全部联系人权限，添加后可在设置中修改。",
    );
    dict.set("contacts.new.target_label", "对方邀请链接、handle 或账号");
    dict.set(
        "contacts.new.target_placeholder",
        "粘贴邀请链接或输入 alice:example.com",
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
    dict.set("contacts.scope.presence", "在线状态");
    dict.set("contacts.shared_scopes", "共享权限:");
    dict.set("contacts.scope_update.label", "你授予此联系人的权限");
    dict.set("contacts.scope_update.save", "保存权限");
    dict.set("contacts.scope_update.saving", "正在保存权限…");
    dict.set(
        "contacts.scope_update.empty_hint",
        "保存空权限集会暂停此联系人关系，但不会移除联系人。",
    );

    // ── ContactRow ────────────────────────────────────────────────────
    dict.set("contacts.state.pending_incoming", "等待你处理");
    dict.set("notifications.contact_request.title", "新的联系人请求");
    dict.set("notifications.contact_request.review", "查看联系人请求");
    dict.set("contacts.state.pending_outgoing", "等待对方接受");
    dict.set("contacts.state.accepted", "已是联系人");
    dict.set("contacts.state.rejected", "已拒绝");
    dict.set("contacts.state.tombstoned", "已删除");
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
    dict.set("contacts.petname.placeholder", "备注名（仅自己可见）");
    dict.set("contacts.petname.save", "保存备注名");
    dict.set("contacts.petname.saved", "备注名已保存");
    dict.set("contacts.petname.cleared", "备注名已清除");
    dict.set("contacts.petname.badge", "备注名");
    dict.set("contacts.petname.invalid", "备注名无效");
    dict.set("contacts.petname.invalid_principal", "联系人主体无效");
    dict.set("contacts.petname.confusable_warning", "疑似冒充联系人");
    dict.set("contacts.dm.opening", "正在打开私聊…");
    dict.set(
        "contacts.dm.awaiting_founder",
        "等待对方建立这个会话，建好后会自动打开。",
    );
    dict.set("contacts.dm.creating", "正在建立加密会话…");
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
    dict.set("invite_policy.kind.same_station", "同一服务器的用户");
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
    dict.set("realm_admin.invite_divider", "或通过 handle 添加");
    dict.set("realm_admin.invite_by_handle", "通过 handle 添加");
    dict.set("realm_admin.invite_handle_opt_in", "需对方允许");
    dict.set("realm_admin.invite_target_label", "Handle 或邀请地址");
    dict.set("realm_admin.invite_bad_server", "无效的服务器地址:{error}");
}

/// 设置页：领域创建向导（`ak.realm.create`）、空间创建表单
/// （`ak.space.create`）与入口总览。拆分只为让主函数保持可读，
/// key 仍与其他章节共用扁平的 `setup.*` 命名空间。
fn setup_strings(dict: &mut TranslationDict) {
    // 领域向导外壳。
    dict.set("setup.new_realm", "新建 Realm");
    dict.set("setup.create_steps", "创建步骤");
    dict.set("setup.step_progress", "{current} / {total}");
    dict.set("setup.state.draft", "草稿尚未创建");
    dict.set("setup.state.bootstrap", "引导状态");

    // 向导步骤。
    dict.set("setup.step.basics.label", "基本信息");
    dict.set("setup.step.basics.subtitle", "名称与用途");
    dict.set("setup.step.boundary.label", "边界");
    dict.set("setup.step.boundary.subtitle", "三条策略轴");
    dict.set("setup.step.create.label", "创建");
    dict.set("setup.step.create.subtitle", "确认并创建");
    dict.set("setup.step.done.label", "完成");
    dict.set("setup.step.done.subtitle", "打开已创建的 Realm");

    // 基本信息。
    dict.set("setup.field.realm_title", "Realm 名称");
    dict.set(
        "setup.field.realm_title_placeholder",
        "工程、研究、设计系统…",
    );
    dict.set("setup.field.summary", "简介");
    dict.set(
        "setup.field.realm_summary_placeholder",
        "这个 Realm 用来做什么。",
    );
    dict.set("setup.field.realm_alias", "Realm 别名");
    dict.set("setup.field.realm_alias_placeholder", "engineering");

    // 边界。
    dict.set("setup.axis.discoverability", "可发现性");
    dict.set(
        "setup.axis.discoverability.question",
        "谁可以发现这个 Realm 的存在？",
    );
    dict.set("setup.axis.discoverability.unset", "尚未设置发现策略。");
    dict.set("setup.axis.join_rule", "加入规则");
    dict.set("setup.axis.join_rule.question", "主体如何成为成员？");
    dict.set("setup.axis.join_rule.unset", "尚未设置加入方式。");
    dict.set("setup.axis.history_access", "历史访问");
    dict.set(
        "setup.axis.history_access.question",
        "新成员可以读到哪些历史？",
    );
    dict.set("setup.axis.history_access.unset", "尚未设置历史访问范围。");
    dict.set("setup.axis.encryption", "加密");
    dict.set("setup.axis.encryption.question", "保护方式");
    dict.set("setup.axis.encryption.unset", "尚未设置加密配置。");
    dict.set("setup.axis.encryption.locked", "创建后不可更改。");
    dict.set("setup.axis.content_scheme", "内容方案");
    dict.set(
        "setup.axis.content_scheme.question",
        "这个 Realm 使用哪种 MLS 内容方案？",
    );
    dict.set("setup.axis.content_scheme.unset", "尚未设置内容方案。");
    dict.set(
        "setup.axis.content_scheme.prejoin_forced",
        "加入前历史使用 content_scheme=mls_exporter_aead_v1。",
    );
    dict.set(
        "setup.axis.content_scheme.capability_only",
        "仅表示能力——实际投递仍取决于历史可见性。",
    );
    dict.set("setup.axis.security_class", "安全等级");
    dict.set(
        "setup.axis.security_class.question",
        "联邦与审计默认值的整体姿态。",
    );
    dict.set("setup.axis.security_class.unset", "尚未设置安全等级。");
    dict.set("setup.axis.federation_policy", "联邦策略");
    dict.set(
        "setup.axis.federation_policy.question",
        "这个 Realm 如何与其他部署互通？",
    );
    dict.set("setup.axis.federation_policy.unset", "尚未设置联邦策略。");
    dict.set(
        "setup.axis.federation_policy.high_assurance",
        "高保障等级只允许 restricted、closed 或 quarantine 联邦。",
    );
    dict.set("setup.axis.hash_profile", "哈希配置");
    dict.set(
        "setup.axis.hash_profile.question",
        "规范化哈希所用的摘要算法。",
    );
    dict.set("setup.axis.hash_profile.unset", "尚未设置哈希配置。");
    dict.set(
        "setup.boundary.advanced_summary",
        "高级（联邦策略 / 哈希配置）",
    );

    // 创建阻塞与进度。
    dict.set(
        "setup.blocker.already_created",
        "Realm 已创建，请从“完成”步骤继续。",
    );
    dict.set("setup.blocker.sign_in", "创建 Realm 前请先登录。");
    dict.set(
        "setup.blocker.secure_store",
        "设备签名存储仍在启动，请稍后重试。",
    );
    dict.set(
        "setup.blocker.account_context_unavailable",
        "当前账户上下文不可用。",
    );
    dict.set("setup.blocker.creating", "正在创建 Realm…");
    dict.set(
        "setup.error.session_expired",
        "会话已过期。请刷新或重新登录后再创建 Realm。",
    );

    // 引导进度面包屑，创建成功后以 " · " 连接显示在“引导状态”一行。
    dict.set(
        "setup.progress.accepted",
        "Realm {id} 已受理;正在完成加密设置",
    );
    dict.set("setup.progress.created", "已创建 {id}");
    dict.set(
        "setup.progress.canonical_policy",
        "规范策略 {discoverability} / {join_rule} / {history_access}",
    );
    dict.set("setup.progress.plaintext_services", "未加密服务:{count} 个");
    dict.set("setup.progress.mls_ready_local", "本设备加密已就绪");
    dict.set(
        "setup.progress.floor_required",
        "元数据与内容均为端到端加密",
    );
    dict.set(
        "setup.error.signer_not_ready",
        "签名密钥尚未就绪,无法创建 Realm。请稍后重试。详情:{error}",
    );
    dict.set("setup.error.create_failed", "创建失败:{error}");
    dict.set("setup.error.created_then_failed", "已创建 {id};{error}");
    dict.set("setup.error.invalid_server_url", "无效的服务器地址:{error}");
    dict.set(
        "setup.error.invalid_default_strand_id",
        "服务器接受的默认 Strand 标识符无效:{error}",
    );

    // 完成。
    dict.set("setup.done.created_realm", "已创建的 Realm");
    dict.set("setup.done.empty", "请先创建 Realm，再打开下一个上下文。");

    // 加密领域的恢复门禁。
    dict.set(
        "setup.recovery_gate.aria",
        "创建加密 Realm 前先设置恢复方式",
    );
    dict.set("setup.recovery_gate.title", "请先设置恢复方式");
    dict.set("setup.recovery_gate.badge", "加密 Realm");
    dict.set(
        "setup.recovery_gate.body",
        "这个 Realm 是端到端加密的。如果你丢失本设备且没有配置恢复密钥或备份，其中的内容将永久无法恢复。请先设置 24 词恢复密钥并备份密钥，再创建它。",
    );
    dict.set(
        "setup.recovery_gate.checking",
        "正在检查恢复设置，请稍后重试。",
    );

    // 操作。
    dict.set("setup.action.back", "上一步");
    dict.set("setup.action.next_boundary", "下一步：边界");
    dict.set("setup.action.next_create", "下一步：创建");
    dict.set("setup.action.create_realm", "创建 Realm");
    dict.set("setup.action.finishing", "正在完成设置…");
    dict.set("setup.action.open_realm", "打开 Realm");
    dict.set("setup.action.setup_recovery_key", "设置恢复密钥");

    setup_option_strings(dict);
    setup_policy_hint_strings(dict);
    setup_space_strings(dict);
    setup_overview_strings(dict);
}

/// `views::setup::data` 中创建表单选项表的标签与说明。
/// key 形状为 `setup.opt.<轴>.<取值>[.hint]`。
fn setup_option_strings(dict: &mut TranslationDict) {
    dict.set("setup.opt.discoverability.public", "公开");
    dict.set(
        "setup.opt.discoverability.public.hint",
        "可在搜索中找到。存在性与加入入口可以被广泛披露。",
    );
    dict.set("setup.opt.discoverability.listed", "列出");
    dict.set(
        "setup.opt.discoverability.listed.hint",
        "在搜索中可见，但与如何加入、能看到哪些历史仍然相互独立。",
    );
    dict.set("setup.opt.discoverability.restricted", "受限");
    dict.set(
        "setup.opt.discoverability.restricted.hint",
        "只有已满足服务端策略的主体才能在目录中看到它。",
    );
    dict.set("setup.opt.discoverability.unlisted", "不公开列出");
    dict.set(
        "setup.opt.discoverability.unlisted.hint",
        "无法在搜索中浏览。进入依赖直接链接或明确引用。",
    );
    dict.set("setup.opt.discoverability.invite_only", "仅限邀请");
    dict.set(
        "setup.opt.discoverability.invite_only.hint",
        "只向被明确邀请的主体披露存在性。",
    );
    dict.set("setup.opt.discoverability.secret", "保密");
    dict.set(
        "setup.opt.discoverability.secret.hint",
        "不应向未授权的查看者披露该 Realm 的存在。",
    );

    dict.set("setup.opt.join_rule.public", "公开");
    dict.set(
        "setup.opt.join_rule.public.hint",
        "任何能看到该 Realm 的人都可以直接加入，无需单独审批。",
    );
    dict.set("setup.opt.join_rule.invite", "邀请");
    dict.set(
        "setup.opt.join_rule.invite.hint",
        "加入需要成员或管理员明确授予准入。",
    );
    dict.set("setup.opt.join_rule.knock", "申请");
    dict.set(
        "setup.opt.join_rule.knock.hint",
        "申请者可以请求进入并等待审核。",
    );
    dict.set("setup.opt.join_rule.restricted", "受限");
    dict.set(
        "setup.opt.join_rule.restricted.hint",
        "即使 Realm 可被发现，加入仍取决于策略或声明。",
    );

    dict.set("setup.opt.history_access.since_join", "加入后历史");
    dict.set(
        "setup.opt.history_access.since_join.hint",
        "成员只能恢复当前成员身份加入之后的历史。此状态为终态，不能再放宽。",
    );
    dict.set(
        "setup.opt.history_access.all_history_for_current_members",
        "当前成员可访问全部历史",
    );
    dict.set(
        "setup.opt.history_access.all_history_for_current_members.hint",
        "每个当前成员都可恢复该领域保留的全部历史；以后只能单向收紧为加入后历史。",
    );

    dict.set("setup.opt.encryption_profile.mls_rfc9420", "加密");
    dict.set(
        "setup.opt.encryption_profile.mls_rfc9420.hint",
        "推荐。元数据与内容均使用 MLS 端到端加密。",
    );
    dict.set("setup.opt.encryption_profile.none", "不加密");
    dict.set(
        "setup.opt.encryption_profile.none.hint",
        "明文对服务器可见。仅用于公开 Realm。",
    );

    dict.set(
        "setup.opt.content_scheme.mls_exporter_aead_v1",
        "MLS exporter AEAD",
    );
    dict.set(
        "setup.opt.content_scheme.mls_exporter_aead_v1.hint",
        "content_scheme=mls_exporter_aead_v1。可以把加入之前的历史授予新成员。前向保密性降为按 epoch 粒度。",
    );
    dict.set("setup.opt.content_scheme.mls_rfc9420", "MLS PrivateMessage");
    dict.set(
        "setup.opt.content_scheme.mls_rfc9420.hint",
        "content_scheme=mls_rfc9420。加入前的历史永远无法共享给后加入者。前向保密性为按消息粒度。",
    );

    dict.set("setup.opt.security_class.standard", "标准");
    dict.set(
        "setup.opt.security_class.standard.hint",
        "默认姿态。联邦策略可按 Realm 设置为开放或受限。",
    );
    dict.set("setup.opt.security_class.high_assurance", "高保障");
    dict.set(
        "setup.opt.security_class.high_assurance.hint",
        "收紧的默认值：联邦被强制为 restricted/closed/quarantine，并记录审计信号。",
    );

    dict.set("setup.opt.federation_policy.open", "开放");
    dict.set(
        "setup.opt.federation_policy.open.hint",
        "任何对端都可交互。security_class=high_assurance 时不允许。",
    );
    dict.set("setup.opt.federation_policy.restricted", "受限");
    dict.set(
        "setup.opt.federation_policy.restricted.hint",
        "对端白名单（治理 / 组织审核）。高保障等级的默认值。",
    );
    dict.set("setup.opt.federation_policy.closed", "关闭");
    dict.set(
        "setup.opt.federation_policy.closed.hint",
        "完全不联邦。用于纯内部 Realm。",
    );
    dict.set("setup.opt.federation_policy.quarantine", "隔离");
    dict.set(
        "setup.opt.federation_policy.quarantine.hint",
        "接受入站但先扣留待审。出站被阻断。",
    );

    dict.set("setup.opt.hash_profile.sha256", "SHA-256");
    dict.set(
        "setup.opt.hash_profile.sha256.hint",
        "默认值。各处都可互操作。",
    );
    dict.set("setup.opt.hash_profile.sha512", "SHA-512");
    dict.set(
        "setup.opt.hash_profile.sha512.hint",
        "更长的摘要。仅在部署策略要求时选择。",
    );
    dict.set("setup.opt.hash_profile.sha3_256", "SHA3-256");
    dict.set(
        "setup.opt.hash_profile.sha3_256.hint",
        "Keccak 系列。用于强制要求 SHA-3 的 FIPS 兼容部署。",
    );
    dict.set("setup.opt.hash_profile.blake3", "BLAKE3");
    dict.set(
        "setup.opt.hash_profile.blake3.hint",
        "在现代 CPU 上更快。仅在所有对端都支持 BLAKE3 时使用。",
    );

    dict.set("setup.opt.space_kind.space", "空间（通用）");
    dict.set("setup.opt.space_kind.space.hint", "");
    dict.set("setup.opt.space_kind.project", "项目");
    dict.set(
        "setup.opt.space_kind.project.hint",
        "一项工作的顶层范围；通常包含看板 / 列表。",
    );
    dict.set("setup.opt.space_kind.folder", "文件夹");
    dict.set(
        "setup.opt.space_kind.folder.hint",
        "纯导航容器。承载子空间 / 流程，但本身不是工作流。",
    );
    dict.set("setup.opt.space_kind.board", "看板");
    dict.set(
        "setup.opt.space_kind.board.hint",
        "看板 / 流水线视图。单元格跟踪流程的位置（rank cas-register）。",
    );
    dict.set("setup.opt.space_kind.list", "列表");
    dict.set(
        "setup.opt.space_kind.list.hint",
        "有序列表视图。适合待办 / 分诊 / 队列类界面。",
    );
}

/// `views::setup::helpers` 产生的跨轴策略告警。
fn setup_policy_hint_strings(dict: &mut TranslationDict) {
    dict.set("setup.policy_hint.secret_conflict", "组合无效");
    dict.set(
        "setup.policy_hint.secret_conflict.body",
        "保密空间不能同时公开准入或提供全网可读的历史。",
    );
    dict.set("setup.policy_hint.invite_public", "组合自相矛盾");
    dict.set(
        "setup.policy_hint.invite_public.body",
        "仅限邀请的发现策略配上公开加入，通常说明发现模型没有想清楚。",
    );
    dict.set(
        "setup.content_scheme.prejoin_requires_exporter",
        "加入前历史要求 content_scheme=mls_exporter_aead_v1。",
    );
}

/// `ak.space.create` 表单与空间生命周期操作。
fn setup_space_strings(dict: &mut TranslationDict) {
    dict.set("setup.space.new_space", "新建空间");
    dict.set("setup.space.parent.root", "（根层级——无父级）");
    dict.set("setup.space.not_created", "尚未创建");
    dict.set(
        "setup.space.wire_shape.body",
        "ak.space.create 事件 + 可选的 parent_space_id。下方的生命周期操作会派发 ak.space.archive / restore / tombstone。",
    );
    dict.set("setup.space.lifecycle.hint", "归档 / 恢复 / 墓碑标记");
    dict.set(
        "setup.space.error.create_failed",
        "create_space 失败:{error}",
    );
    dict.set("setup.space.error.archive_failed", "归档失败:{error}");
    dict.set("setup.space.error.restore_failed", "恢复失败:{error}");
    dict.set("setup.space.error.tombstone_failed", "墓碑标记失败:{error}");
    dict.set(
        "setup.space.error.invalid_base_url",
        "无效的服务器地址:{error}",
    );
    dict.set("setup.space.field.title", "空间标题");
    dict.set(
        "setup.space.field.title_placeholder",
        "待办、路线图、新人引导…",
    );
    dict.set("setup.space.field.kind", "类型");
    dict.set("setup.space.field.summary_placeholder", "可选的描述。");
    dict.set("setup.space.field.parent", "父空间（可选）");
    dict.set(
        "setup.space.parent.no_realm",
        "请从侧栏的 Realm 或空间行选择“新建空间”，以确定所属 Realm。",
    );
    dict.set(
        "setup.space.parent.no_siblings",
        "该 Realm 下还没有同级空间——保留在根层级。",
    );
    dict.set(
        "setup.space.advanced_summary",
        "高级（新资源的跨 Realm 默认值）",
    );
    dict.set("setup.space.action.create", "创建空间");
    dict.set("setup.space.outcome", "结果");
    dict.set("setup.space.outcome.hint", "空间创建");
    dict.set("setup.space.created", "已创建的空间");
    dict.set("setup.space.status", "状态");
    dict.set("setup.space.wire_shape", "线上结构");
    dict.set("setup.space.lifecycle", "生命周期操作");
    dict.set(
        "setup.space.lifecycle.empty",
        "请先在上方创建空间，才能对它执行生命周期操作。",
    );
    dict.set("setup.space.action.archive", "归档");
    dict.set(
        "setup.space.action.archive.title",
        "将状态置为已归档；服务端不会级联。",
    );
    dict.set("setup.space.action.restore", "恢复");
    dict.set(
        "setup.space.action.restore.title",
        "已归档 → 活跃；仅在已归档状态下有效。",
    );
    dict.set("setup.space.action.tombstone", "墓碑标记");
    dict.set(
        "setup.space.action.tombstone.title",
        "不可逆。若仍存在活跃的子空间 / 位置流程，服务端会拒绝。",
    );
    dict.set(
        "setup.space.tombstone_warning",
        "墓碑标记不可逆——只要还有任何子空间或位置流程处于活跃状态，服务端就会以 space_has_live_dependents 拒绝（规范 §3.4）。",
    );
    dict.set(
        "setup.space.state.submitting_create",
        "正在提交 ak.space.create…",
    );
    dict.set(
        "setup.space.state.submitting_archive",
        "正在提交 ak.space.archive…",
    );
    dict.set(
        "setup.space.state.submitting_restore",
        "正在提交 ak.space.restore…",
    );
    dict.set(
        "setup.space.state.submitting_tombstone",
        "正在提交 ak.space.tombstone…",
    );
    dict.set(
        "setup.space.state.created",
        "已在 {realm}{parent} 内创建空间 {id}（kind={kind}）",
    );
    dict.set("setup.space.state.archived", "已归档 {id}");
    dict.set("setup.space.state.restored", "已恢复 {id}");
    dict.set("setup.space.state.tombstoned", "已墓碑标记 {id}（不可逆）");
}

/// 设置入口总览。
fn setup_overview_strings(dict: &mut TranslationDict) {
    dict.set("setup.overview.surfaces", "设置入口");
    dict.set("setup.overview.surfaces.hint", "单一职责的入口");
    dict.set("setup.overview.realm.hint", "安全边界引导");
    dict.set("setup.overview.realm.open", "打开新建 Realm");
    dict.set("setup.overview.space.hint", "Realm 内的导航容器");
    dict.set(
        "setup.overview.space.body",
        "把鼠标悬停在左侧栏的 Realm 或空间上，点击行内的 + ——这是标准入口，因为它会替你预填父级上下文。下面的链接会打开一个空白表单（你需要自己选择 Realm）。",
    );
    dict.set("setup.overview.space.open", "打开空白表单");
    dict.set("setup.overview.onboarding", "新人引导");
    dict.set("setup.overview.onboarding.hint", "身份引导");
    dict.set("setup.overview.onboarding.open", "打开新人引导");
    dict.set("setup.overview.search", "搜索");
    dict.set("setup.overview.search.hint", "参与者 / handle / Realm");
    dict.set("setup.overview.search.open", "打开搜索");
    dict.set("setup.overview.board", "看板");
    dict.set("setup.overview.board.hint", "引导完成之后");
    dict.set("setup.overview.board.open_current", "打开当前 Realm");
    dict.set("setup.overview.board.open", "打开看板");
    dict.set("setup.overview.moved", "变更说明");
    dict.set("setup.overview.moved.hint", "信息架构梳理");
    dict.set("setup.overview.badge.onboarding", "新人引导 = 身份引导");
    dict.set("setup.overview.badge.search", "搜索 = 发现与人");
    dict.set("setup.overview.badge.realm", "新建 Realm = 安全边界引导");
    dict.set("setup.overview.badge.settings", "设置 = 恢复与运维");
}

/// `app::feature_gate` 解析的面包屑 / 上下文栏标签。
fn route_label_strings(dict: &mut TranslationDict) {
    dict.set("route.dashboard", "主页");
    dict.set("route.login", "登录");
    dict.set("route.register", "创建身份");
    dict.set("route.realms_manage", "管理 Realm");
    dict.set("route.principal_control", "身份控制");
    dict.set("route.realm", "Realm");
    dict.set("route.chat", "讨论");
    dict.set("route.direct", "私聊");
    dict.set("route.contacts_manage", "管理联系人");
    dict.set("route.contacts", "联系人");
    dict.set("route.files", "文件");
    dict.set("route.directory", "搜索");
    dict.set("route.setup", "设置向导");
    dict.set("route.setup_realms", "新建 Realm");
    dict.set("route.setup_new_space", "新建空间");
    dict.set("route.settings", "设置");
    dict.set("route.notifications", "通知");
    dict.set("route.verify_device", "验证设备");
    dict.set("route.realm_members", "成员");
    dict.set("route.circles", "圈子");
    dict.set("route.realm_admin", "Realm 设置");
    dict.set("route.realm_admin.profile", "资料");
    dict.set("route.realm_admin.access", "访问策略");
    dict.set("route.realm_admin.security", "安全与 MLS");
    dict.set("route.realm_admin.federation", "联邦信任");
    dict.set("route.realm_admin.repair", "修复与危险操作");
    dict.set("route.audit", "审计日志");
    dict.set("route.developer", "开发者工具");
    dict.set("route.board", "看板视图");
    dict.set("route.call", "通话");
    dict.set("route.recovery", "恢复");
    dict.set("route.devices", "设备");
    dict.set("route.devices_pair", "添加设备");
    dict.set("route.onboarding", "新人引导");
    dict.set("route.quarantine", "待你决定");
    dict.set("route.applets", "小程序");

    dict.set("route.settings.server", "账号与服务器");
    dict.set("route.settings.storage", "数据与同步");
    dict.set("route.settings.encryption", "安全");
    dict.set("route.settings.mimi", "集成");
    dict.set("route.settings.privacy", "隐私与分享");
    dict.set("route.settings.invite_policy", "谁可以邀请我");
    dict.set("route.settings.blocklist", "已屏蔽的参与者");
    dict.set("route.settings.capabilities", "能力");
    dict.set("route.settings.theme", "外观与语言");
    dict.set("route.settings.release", "诊断");
}

/// Plain-language copy for the inline prompts, banners, and manage
/// pages migrated off hardcoded literals. Keep both locales in this
/// same list shape: every key gets an en value here and a zh value in
/// `zh.rs`'s `prompt_copy_strings`, and the parity test enforces it.
fn prompt_copy_strings(dict: &mut TranslationDict) {
    dict.set("did_health.label.degraded", "受限");
    dict.set("did_health.label.metadata", "元数据");
    dict.set("did_health.label.outage", "离线");
    dict.set("did_health.label.server_metadata", "服务器元数据");
    dict.set("did_health.title.degraded", "身份核验受限");
    dict.set("did_health.title.metadata_mismatch", "身份信息格式不匹配");
    dict.set("did_health.title.unavailable", "身份核验离线");
    dict.set("did_health.title.service_unavailable", "身份服务不可用");
    dict.set(
        "did_health.detail.metadata_mismatch",
        "身份服务已响应，但当前应用无法读取其数据格式。请刷新或更新应用；身份检查会自动重试。",
    );
    dict.set(
        "did_health.detail.partial",
        "部分身份核验当前不可用。涉及信任的操作仍处于暂停状态。",
    );
    dict.set(
        "did_health.detail.unavailable",
        "身份服务暂时不可用，等待服务器恢复。已保存的内容仍可查看。",
    );
    dict.set(
        "did_health.detail.server_metadata",
        "此服务器未提供预期的身份元数据,身份核验已被阻止。",
    );
    dict.set(
        "did_health.detail.blocked",
        "在服务恢复之前,身份核验无法进行。",
    );
    dict.set(
        "recovery_setup.err_requires_account",
        "请先登录,再设置恢复密钥。",
    );
    dict.set(
        "recovery_setup.err_generation_failed",
        "无法生成恢复密钥({error})。请重试。",
    );
    dict.set(
        "recovery_setup.status_after_generate",
        "请把这 24 个词抄写下来离线保存,然后重新输入。目前还没有发布任何内容。",
    );
    dict.set("recovery_setup.generating", "正在生成恢复密钥…");
    dict.set(
        "recovery_setup.generating_replacement",
        "正在生成新的恢复密钥…",
    );
    dict.set(
        "recovery_setup.save_first_guard",
        "请先保存这 24 个词,然后在下方确认。",
    );
    dict.set("recovery_setup.aria_label", "设置恢复密钥");
    dict.set("recovery_setup.title", "设置恢复密钥(24 词)");
    dict.set("recovery_setup.subtitle", "启用加密前必需");
    dict.set("recovery_setup.device_unauthorized", "此设备尚未获得保存恢复数据的授权。这些词只显示在当前屏幕上。请先授权此设备并用相同的词重试,或使用已有的恢复密钥恢复。");
    dict.set("recovery_setup.intro", "在此生成 24 个词,并把它们抄写下来妥善离线保存,然后即可使用加密 Realm。Arkret 无法帮你找回这些词。");
    dict.set("recovery_setup.generated_key_label", "恢复密钥(24 词)");
    dict.set("recovery_setup.copied", "已复制");
    dict.set("recovery_setup.copy_words", "复制词句");
    dict.set("recovery_setup.download", "下载 .txt");
    dict.set(
        "recovery_setup.save_warning",
        "请立即保存这些词。它们不会被上传,关闭此窗口后将无法再次查看。",
    );
    dict.set("recovery_setup.confirm_label", "重新输入已保存的恢复密钥");
    dict.set(
        "recovery_setup.confirm_placeholder",
        "输入或粘贴你保存的 24 个词",
    );
    dict.set(
        "recovery_setup.confirm_hint",
        "只有完全匹配才能继续。如果抄错了,请生成新密钥并保存新的那份。",
    );
    dict.set("recovery_setup.restore_button", "使用已有的恢复密钥恢复");
    dict.set("recovery_setup.close", "关闭");
    dict.set("recovery_setup.try_again", "重试");
    dict.set("recovery_setup.generating_button", "正在生成…");
    dict.set("recovery_setup.not_now", "暂不设置");
    dict.set("recovery_setup.regenerate", "生成新密钥");
    dict.set("recovery_setup.close_unpublished", "关闭且暂不发布");
    dict.set(
        "recovery_setup.err_word_count",
        "你输入了 24 个词中的 {entered} 个。请补全后再确认。",
    );
    dict.set(
        "recovery_setup.err_word_mismatch",
        "第 {index} 个词与此恢复密钥不匹配。请修正后再次确认。",
    );
    dict.set(
        "recovery_setup.publishing",
        "已确认保存无误。正在发布恢复设置和首个加密备份…",
    );
    dict.set(
        "recovery_setup.metadata_save_failed",
        "恢复已设置完成,但本地信息未能保存到此设备。",
    );
    dict.set("recovery_setup.confirm_button", "确认已保存的密钥");
    dict.set("identity.tier.cached", "缓存名称");
    dict.set(
        "identity.tier.cached_detail",
        "这是本地保存的旧名称,刚才没能重新核对。",
    );
    dict.set("identity.tier.name_only", "未核验名称");
    dict.set(
        "identity.tier.name_only_detail",
        "这是此前记录下来的名称,不是核验过的名称。",
    );
    dict.set("identity.tier.unresolved", "名称不可用");
    dict.set(
        "identity.tier.unresolved_detail",
        "没能查到这个账号的名称,这里显示的是账号标识。",
    );
    dict.set("settings.devices.title", "设备访问");
    dict.set(
        "settings.devices.subtitle",
        "查看受信任的设备,或批准一台新设备。",
    );
    dict.set("settings.devices.help", "管理绑定到你账户的设备。吊销设备会把它移出活跃设备集合,并在它参与的每个端到端加密 Realm 中移除对应的 MLS 叶节点。");
    dict.set("settings.devices.tabs_aria_label", "设备设置");
    dict.set("settings.devices.tab_list", "设备");
    dict.set("settings.devices.tab_add", "添加设备");
    dict.set("settings.devices.refresh", "刷新");
    dict.set("settings.devices.active_title", "活跃设备");
    dict.set("settings.devices.empty_title", "还没有加载到设备");
    dict.set(
        "settings.devices.empty_message",
        "正在加载你的设备…也可以点击“刷新”重试。",
    );
    dict.set("settings.devices.column_device", "设备");
    dict.set("settings.devices.column_verification", "验证状态");
    dict.set("settings.devices.column_authorized", "授权时间");
    dict.set("settings.devices.column_actions", "操作");
    dict.set("settings.devices.this_device", "当前设备");
    dict.set("settings.devices.state_verified", "已验证");
    dict.set("settings.devices.state_unverified", "未验证");
    dict.set("settings.devices.state_revoked", "已吊销");
    dict.set("settings.devices.state_title", "设备验证状态:{state}");
    dict.set("settings.devices.revoke_title", "吊销设备");
    dict.set(
        "settings.devices.revoke_recovery_label",
        "恢复密钥(24 个词)",
    );
    dict.set(
        "settings.devices.revoke_recovery_placeholder",
        "你的 24 词恢复密钥 —— 轮换加密历史备份时必须提供",
    );
    dict.set("settings.devices.revoke_confirm", "确认吊销");
    dict.set("settings.devices.accept_title", "用链接批准");
    dict.set(
        "settings.devices.accept_body",
        "在此粘贴新设备生成的完整配对链接。核对比对码与设备身份后批准。",
    );
    dict.set(
        "settings.devices.accept_placeholder",
        "粘贴完整配对链接(…#token=…&proof=…)",
    );
    dict.set("settings.devices.session_active", "已登录");
    dict.set("settings.devices.session_inactive", "未登录");
    dict.set("settings.devices.revoke_self_blocked", "不能吊销当前设备");
    dict.set("settings.devices.revoke", "吊销");
    dict.set("settings.devices.revoke_body_before", "这会写入 ");
    dict.set("settings.devices.revoke_body_after", " 到你的主控 Realm,把该设备移出它参与的每个端到端加密 Realm,并轮换账户 MLS 历史密钥。此操作无法撤销。");
    dict.set("settings.devices.accept_resolving", "正在解析…");
    dict.set("settings.devices.accept_resolve", "解析链接");
    dict.set(
        "settings.devices.accept_rejected",
        "已忽略这次配对请求,没有批准任何设备。",
    );
    dict.set("settings.devices.accept_device_name", "设备名称");
    dict.set("settings.devices.accept_device_id", "设备标识");
    dict.set("settings.devices.accept_key_fingerprint", "密钥指纹");
    dict.set("settings.devices.accept_gate_audience", "批准账户服务器");
    dict.set("settings.devices.accept_unnamed_device", "未提供");
    dict.set("settings.devices.revoke_threat_note", "吊销不等于远程擦除。它无法删除该设备上已经复制走的密钥或缓存历史。请把丢失或被盗的设备当作仍能读取它在吊销前留存的一切内容。");
    dict.set("audit.title", "审计日志");
    dict.set("audit.help", "有些 Realm 会记录每一次读取,有些会记录每一次写入。此视图只读,只显示这台设备已经看到的记录。");
    dict.set("audit.access_events", "已记录的读取");
    dict.set("audit.access_events_hint", "在 Realm 记录每次读取时产生");
    dict.set("audit.write_receipts", "已记录的写入");
    dict.set("audit.write_receipts_hint", "在 Realm 记录每次写入时产生");
    dict.set("audit.total_observed", "本机共计");
    dict.set("audit.total_observed_hint", "仅统计这台设备已同步到的部分");
    dict.set("audit.empty_title", "还没有审计记录");
    dict.set(
        "audit.empty_message",
        "目前还没有任何记录。只有在设置要求记录的 Realm 中才会出现。",
    );
    dict.set("quarantine.title", "待你决定");
    dict.set(
        "quarantine.status",
        "等你决定的事项只为你自己私密保存。等同意流程可用后,这里会出现审阅控件。",
    );
    dict.set("quarantine.invite_delivery_title", "邀请");
    dict.set(
        "quarantine.invite_delivery_hint",
        "有人邀请你加入一个 Realm。同意会建立一条 consent 授权;是否接受这封邀请本身,你仍可另行决定。",
    );
    dict.set("quarantine.consent_request_title", "联系许可请求");
    dict.set(
        "quarantine.consent_request_hint",
        "有人请求你允许他联系你。同意只会建立一条 consent 授权,没有别的对象要接受;对方之后会自己再来。",
    );
    dict.set("quarantine.empty", "目前没有需要你决定的事项。");
    dict.set("quarantine.scope_label", "请求用于");
    dict.set(
        "consent.grant.grantee_station_label",
        "被授权方 Station DID（除非上方填写完整账号选择器，否则必填）",
    );
    dict.set(
        "consent.request.holder_station_label",
        "持有方 Station DID（除非上方填写完整账号选择器，否则必填）",
    );
    dict.set("quarantine.expires_label", "超时丢弃");
    dict.set("theme.switcher_aria_label", "主题");
    dict.set("common.delete", "删除");
    dict.set("app.boot.opening_secure_storage", "正在打开安全存储");
    dict.set("app.boot.loading_keys", "正在加载账户与设备的加密密钥…");
    dict.set("app.recovery.incomplete_title", "恢复设置尚未完成");
    dict.set("app.recovery.incomplete_body", "在依赖这个账户之前，先生成你的恢复密钥（24 个词）。备份在服务器上只以密文保存；Arkret 无法替你找回这 24 个词。");
    dict.set("app.recovery.configure", "去设置恢复");
    dict.set("app.recovery.history_status", "加密历史状态");
    dict.set("app.recovery.history_status_body", "恢复加密历史需要一份账户 MLS 密钥材料；如果这是全新账户，等你第一次写入加密内容、生成可备份的材料之后，应用会再次提示。");
    dict.set("app.nav.close_menu", "关闭菜单");
    dict.set("app.nav.open_menu", "打开菜单");
    dict.set("app.nav.main_navigation", "主导航");
    dict.set("app.nav.resize_menu", "拖动调整菜单宽度");
    dict.set("app.nav.scope_toggle", "协作与联系人");
    dict.set("app.nav.show_navigation", "显示导航");
    dict.set("app.nav.hide_navigation", "隐藏导航");
    dict.set("app.brand.home", "Inkson | Arkret 首页");
    dict.set("app.main_content", "主内容");
    dict.set("app.sidebar.hide_own_agents", "隐藏你的 AI 助理");
    dict.set("app.sidebar.show_own_agents", "显示你的 AI 助理");
    dict.set("app.sidebar.opening", "正在打开…");
    dict.set("app.sidebar.agent_badge", "AI 助理");
    dict.set("app.sidebar.remark", "备注");
    dict.set("app.sidebar.remark_title", "本地备注（只对这个账户可见）");
    dict.set("app.sidebar.direct_badge", "私聊");
    dict.set("app.sidebar.agent_count", "助理 {count}");
    dict.set("app.sidebar.contact_actions", "联系人操作");
    dict.set("app.sidebar.close_row_actions", "关闭这一行的操作");
    dict.set("app.sidebar.delete_contact", "删除联系人");
    dict.set("app.topbar.current_view", "当前视图：{surface}");
    dict.set("app.topbar.open_global_search", "打开全局搜索");
    dict.set("app.account.open_settings", "打开设置");
    dict.set("app.account.did", "DID");
    dict.set("app.account.server", "服务器");
    dict.set("app.account.refresh_session", "刷新会话");
    dict.set("app.account.log_out", "退出登录");
    dict.set("theme.switch_to_light", "切换到浅色主题");
    dict.set("theme.switch_to_night", "切换到深色主题");
    dict.set("account.not_signed_in", "尚未登录");
    dict.set("account.refresh_then_sign_in", "先刷新服务器元数据，再登录");
    dict.set("visibility.pill_title", "谁可以找到并看到它");
    dict.set("moderation.workbench_aria_label", "内容处置");
    dict.set("moderation.decide_title", "记录一次处置");
    dict.set("moderation.decide_badge", "处置");
    dict.set("moderation.target_placeholder", "这次处置针对的对象");
    dict.set("moderation.decide_submit", "记录处置");
    dict.set("moderation.standing_title", "生效中的处置");
    dict.set(
        "moderation.standing_empty",
        "这台设备上还没有生效中的处置。",
    );
    dict.set(
        "moderation.decision_row_summary",
        "针对 {target} —— {reason}",
    );
    dict.set("moderation.lift", "撤销处置");
    dict.set("device_pair.aria_label", "有新设备正在请求访问你的账户");
    dict.set("device_pair.title", "新设备请求加入你的账户");
    dict.set("device_pair.subtitle", "设备配对");
    dict.set(
        "device_pair.body",
        "有设备请求加入你的账户。仅当此操作由你发起时才批准——先比对两台设备上显示的下方代码。",
    );
    dict.set("device_pair.platform", "平台:{platform}");
    dict.set("device_pair.expires", "请求过期时间 {time}");
    dict.set("device_pair.compare_code", "请在两台设备上比对此代码");
    dict.set("device_pair.approving", "正在批准…");
    dict.set("device_pair.err_approval_failed", "无法批准该设备:{error}");
    dict.set("device_pair.reject", "拒绝");
    dict.set("device_pair.approve", "批准");
    dict.set(
        "agent_runtime.aria_label",
        "有代理运行时正在请求访问你的账户",
    );
    dict.set("agent_runtime.title", "代理运行时请求批准");
    dict.set("agent_runtime.subtitle", "代理配对");
    dict.set(
        "agent_runtime.body",
        "一个代理运行时请求完成配对。仅当此请求由你发起且代码与运行时屏幕上显示的一致时才批准。",
    );
    dict.set(
        "agent_runtime.replacement_warning",
        "这将替换一个处于活跃或暂停状态的代理的运行时密钥。",
    );
    dict.set("agent_runtime.slug", "标识:{slug}");
    dict.set("agent_runtime.requested", "请求时间 {time}");
    dict.set("agent_runtime.compare_code", "批准前请比对此代码");
    dict.set("agent_runtime.runtime_key", "运行时密钥");
    dict.set("agent_runtime.pairing_expires", "配对过期时间 {time}");
    dict.set("agent_runtime.rejecting", "正在拒绝请求并更换配对代码…");
    dict.set("agent_runtime.rejected", "已拒绝请求并更换配对代码。");
    dict.set(
        "agent_runtime.err_rotate_failed",
        "无法更换配对代码。{error}",
    );
    dict.set("agent_runtime.reject_rotate", "拒绝并更换代码");
    dict.set("agent_runtime.dismiss", "忽略");
    dict.set("agent_runtime.err_no_account", "请先登录,再批准。");
    dict.set(
        "agent_runtime.err_invalid_request",
        "运行时密钥请求无效。{error}",
    );
    dict.set("agent_runtime.approving", "正在批准代理运行时…");
    dict.set(
        "agent_runtime.approved_refresh_failed",
        "运行时密钥已批准({id})。代理的恢复备份刷新失败:{error}",
    );
    dict.set(
        "agent_runtime.approved_current",
        "运行时密钥已批准({id})。代理的恢复备份已是最新。",
    );
    dict.set(
        "agent_runtime.err_approval_failed",
        "无法批准运行时密钥。{error}",
    );
    dict.set("agent_runtime.approving_button", "正在批准…");
    dict.set("agent_runtime.approve", "批准");
    dict.set("manage.realms_title", "管理 Realm");
    dict.set("manage.principal_control_button", "PCR");
    dict.set(
        "manage.principal_control_subtitle",
        "用于系统身份与设备授权，与协作 Realm 分开管理。",
    );
    dict.set("manage.principal_control_purpose_label", "用途");
    dict.set(
        "manage.principal_control_purpose_value",
        "身份、设备授权与恢复控制",
    );
    dict.set("manage.principal_control_realm_id", "Realm ID");
    dict.set(
        "manage.principal_control_no_business_surfaces",
        "该控制面 Realm 不提供 Board、Space、讨论、成员等业务页面。",
    );
    dict.set(
        "manage.principal_control_unavailable",
        "已接受的 Principal Control Realm 尚未进入本地投影。",
    );
    dict.set("manage.back_to_realms", "返回 Realm 管理");
    dict.set(
        "manage.realms_empty_hint",
        "同步完成后,Realm 将显示在这里。",
    );
    dict.set("manage.no_results_hint", "换个搜索词试试,以显示更多结果。");
    dict.set("manage.row_encrypted", "已加密");
    dict.set("manage.row_unencrypted", "未加密");
    dict.set("manage.row_spaces", "{count} 个空间");
    dict.set("manage.contacts_title", "管理联系人");
    dict.set("manage.search_contacts", "搜索联系人");
    dict.set(
        "manage.contacts_empty_hint",
        "加载完成后,你的联系人将显示在这里。",
    );
    dict.set("manage.contacts_no_results", "没有匹配的联系人");
    dict.set("manage.contact_no_scopes", "无共享范围");
    dict.set("manage.contact_dm", "私聊 {state}");
    dict.set("manage.contact_no_dm", "无私聊");
}
