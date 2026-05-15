use std::collections::HashMap;

use chrono::{DateTime, Utc};
use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

/// Supported locales.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Locale {
    #[default]
    En,
    Zh,
    Ar,
}

impl Locale {
    pub fn code(&self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::Zh => "zh",
            Locale::Ar => "ar",
        }
    }

    pub fn from_code(code: &str) -> Self {
        match code {
            "zh" | "zh-CN" | "zh-TW" => Locale::Zh,
            "ar" | "ar-SA" | "ar-EG" => Locale::Ar,
            _ => Locale::En,
        }
    }

    pub fn direction(&self) -> TextDirection {
        match self {
            Locale::Ar => TextDirection::Rtl,
            Locale::En | Locale::Zh => TextDirection::Ltr,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextDirection {
    Ltr,
    Rtl,
}

impl TextDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ltr => "ltr",
            Self::Rtl => "rtl",
        }
    }
}

/// Translation dictionary for a single locale.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TranslationDict {
    pub locale: Locale,
    pub strings: HashMap<String, String>,
}

impl TranslationDict {
    pub fn new(locale: Locale) -> Self {
        Self {
            locale,
            strings: HashMap::new(),
        }
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.strings.insert(key.into(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.strings.get(key).map(|s| s.as_str())
    }
}

/// Global i18n state managed as a Dioxus signal.
pub type I18nSignal = Signal<(Locale, HashMap<String, TranslationDict>)>;

/// Get a translated string by key. Falls back to English, then to the key itself.
pub fn t(signal: &I18nSignal, key: &str) -> String {
    let (locale, dicts) = signal.read().clone();
    translate(locale, &dicts, key)
}

/// Lookup a translated string without requiring a Dioxus runtime.
pub fn translate(locale: Locale, dicts: &HashMap<String, TranslationDict>, key: &str) -> String {
    // Try requested locale
    if let Some(dict) = dicts.get(locale.code()) {
        if let Some(val) = dict.get(key) {
            return val.to_owned();
        }
    }
    // Fallback to English
    if locale != Locale::En {
        if let Some(dict) = dicts.get("en") {
            if let Some(val) = dict.get(key) {
                return val.to_owned();
            }
        }
    }
    // Last resort: return the key itself
    key.to_owned()
}

/// Get the current text direction.
pub fn text_direction(signal: &I18nSignal) -> TextDirection {
    signal.read().0.direction()
}

/// Format a UTC timestamp with locale-specific ordering.
pub fn format_datetime(locale: Locale, timestamp: DateTime<Utc>) -> String {
    match locale {
        Locale::En => timestamp.format("%b %d, %Y %H:%M UTC").to_string(),
        Locale::Zh => timestamp.format("%Y年%m月%d日 %H:%M UTC").to_string(),
        Locale::Ar => timestamp.format("%Y/%m/%d %H:%M UTC").to_string(),
    }
}

/// Format a non-negative integer with locale-appropriate grouping.
pub fn format_number(locale: Locale, value: u64) -> String {
    let grouped = group_decimal(value);
    match locale {
        Locale::En | Locale::Ar => grouped,
        Locale::Zh => grouped.replace(',', " "),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranslationCompleteness {
    pub locale: Locale,
    pub total_keys: usize,
    pub missing_keys: Vec<String>,
}

impl TranslationCompleteness {
    pub fn is_complete(&self) -> bool {
        self.missing_keys.is_empty()
    }

    pub fn missing_count(&self) -> usize {
        self.missing_keys.len()
    }
}

/// Compare a locale dictionary against a reference dictionary.
pub fn translation_completeness(
    reference: &TranslationDict,
    candidate: &TranslationDict,
) -> TranslationCompleteness {
    let mut missing_keys: Vec<String> = reference
        .strings
        .keys()
        .filter(|key| !candidate.strings.contains_key(*key))
        .cloned()
        .collect();
    missing_keys.sort();
    TranslationCompleteness {
        locale: candidate.locale,
        total_keys: reference.strings.len(),
        missing_keys,
    }
}

fn group_decimal(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (idx, ch) in digits.chars().rev().enumerate() {
        if idx > 0 && idx % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

/// Build the default English translation dictionary.
pub fn english_translations() -> TranslationDict {
    let mut dict = TranslationDict::new(Locale::En);

    // Navigation & Shell
    dict.set("app.title", "yougen");
    dict.set("nav.dashboard", "Dashboard");
    dict.set("nav.timeline", "Timeline");
    dict.set("nav.chat", "Chat");
    dict.set("nav.forum", "Forum");
    dict.set("nav.directory", "Directory");
    dict.set("nav.notifications", "Notifications");
    dict.set("nav.settings", "Settings");
    dict.set("nav.login", "Login");
    dict.set("nav.audit", "Audit");
    dict.set("nav.devices", "Devices");

    // Login
    dict.set("login.server", "Server");
    dict.set("login.connection_test", "connection test");
    dict.set("login.server_url", "Server URL");
    dict.set("login.test_connection", "Test Connection");
    dict.set("login.account", "Account");
    dict.set("login.account_did", "Account DID");
    dict.set("login.device_id", "Device ID");
    dict.set("login.passkey", "Passkey Login");
    dict.set("login.oidc", "OIDC Login");
    dict.set("login.dev_login", "Dev Login");
    dict.set("login.session", "Session");
    dict.set("login.disconnected", "disconnected");
    dict.set("login.connected", "connected");
    dict.set("login.soft_logout", "soft-logout");
    dict.set("login.no_token", "No active token");
    dict.set("login.token_active", "Token active");
    dict.set("login.refresh_token", "Refresh Token");
    dict.set("login.re_login", "Re-Login");
    dict.set(
        "login.session_expired",
        "Your session has expired. Log in again to continue.",
    );

    // Timeline
    dict.set(
        "timeline.composer_placeholder",
        "Write a plaintext dev-mode message (Ctrl+Enter to send)",
    );
    dict.set(
        "timeline.encrypted_placeholder",
        "Write an encrypted message (Ctrl+Enter to send)",
    );
    dict.set("timeline.send", "Send");
    dict.set("timeline.reply", "Reply");
    dict.set("timeline.react", "React");
    dict.set("timeline.edit", "Edit");
    dict.set("timeline.redact", "Redact");
    dict.set("timeline.thread", "Thread");
    dict.set("timeline.save", "Save");
    dict.set("timeline.cancel", "Cancel");
    dict.set("timeline.pending", "(pending)");
    dict.set("timeline.edited", "(edited)");
    dict.set("timeline.redacted", "[Message redacted]");
    dict.set("timeline.search_placeholder", "Search messages...");
    dict.set(
        "timeline.no_events",
        "No timeline events yet. Compose a dev-mode message.",
    );
    dict.set("timeline.encrypt_local", "Encrypt Local");
    dict.set("timeline.attach_blob", "Attach Blob");
    dict.set("timeline.report_queue", "Report / Queue");

    // Directory
    dict.set("directory.title", "Directory");
    dict.set("directory.search_placeholder", "Search...");
    dict.set("directory.search", "Search");
    dict.set("directory.load_more", "Load More");
    dict.set("directory.tab.spaces", "Spaces");
    dict.set("directory.tab.organizations", "Organizations");
    dict.set("directory.tab.actors", "Actors");
    dict.set("directory.tab.objects", "Objects");
    dict.set("directory.tab.applets", "Applets");
    dict.set("directory.applet.ping", "Ping");
    dict.set("directory.applet.metadata", "Metadata");

    // Notifications
    dict.set("notifications.title", "Notifications");
    dict.set("notifications.empty", "No notifications loaded.");
    dict.set("notifications.mark_read", "Mark Read");
    dict.set("notifications.archive", "Archive");

    // Settings
    dict.set("settings.title", "Settings");
    dict.set("settings.theme", "Theme");
    dict.set("settings.language", "Language");
    dict.set("settings.light", "Light");
    dict.set("settings.dark", "Dark");
    dict.set("settings.system", "System");

    // Common
    dict.set("common.loading", "Loading...");
    dict.set("common.error", "Error");
    dict.set("common.retry", "Retry");
    dict.set("common.close", "Close");
    dict.set("common.confirm", "Confirm");
    dict.set("common.cancel", "Cancel");
    dict.set("common.save", "Save");
    dict.set("common.delete", "Delete");
    dict.set("common.edit", "Edit");
    dict.set("common.send", "Send");
    dict.set("common.refresh", "Refresh");
    dict.set("common.back", "Back");
    dict.set("common.next", "Next");
    dict.set("common.online", "online");
    dict.set("common.offline", "offline");
    dict.set("common.reconnecting", "reconnecting");

    // R-i18n-002 extra keys for the highest-visibility surfaces.
    dict.set("topbar.search_placeholder", "Jump to a space, view or action…");
    dict.set("topbar.notifications", "Notifications");
    dict.set("topbar.new_space", "New Space");
    dict.set("topbar.account_menu", "Account menu");

    dict.set("login.continue", "Continue");
    dict.set("login.working", "Working...");
    dict.set("login.signed_in_as", "Signed in as");

    dict.set("dashboard.home", "Home");
    dict.set("dashboard.notifications_label", "Notifications");
    dict.set("dashboard.notifications_delta_unread", "Unread and approvals");
    dict.set("dashboard.notifications_delta_signin", "Sign in required");
    dict.set("dashboard.spaces_label", "Spaces");
    dict.set("dashboard.spaces_delta_search", "Search or join a Space");
    dict.set("dashboard.spaces_delta_signin", "Sign in to load spaces");
    dict.set("dashboard.current_space", "Current Space");
    dict.set("dashboard.workspace_setup", "Workspace Setup");
    dict.set("dashboard.workspace_setup_delta", "Bootstrap your first Space and initial policy");
    dict.set("dashboard.onboarding", "Onboarding");
    dict.set("dashboard.onboarding_steps", "4 steps");
    dict.set("dashboard.onboarding_delta", "Identity, device, and recovery setup");
    dict.set("dashboard.recent_spaces", "Recent Spaces");
    dict.set("dashboard.no_spaces", "No spaces loaded");
    dict.set("dashboard.no_spaces_help", "The connected server did not return spaces yet.");
    dict.set("dashboard.no_session_help", "The client is not showing placeholder spaces.");

    dict.set("notifications.archived", "Show archived");
    dict.set("notifications.mark_all_read", "Mark all read");
    dict.set("notifications.empty_state", "No notifications loaded.");

    dict.set("composer.send", "Send");
    dict.set("composer.encrypted_toggle", "Encrypt locally");
    dict.set("composer.plaintext_warning", "Plaintext messages may be visible to the configured server.");

    dict.set("command_palette.spaces", "Spaces");
    dict.set("command_palette.jump_to", "Jump to");
    dict.set("command_palette.empty", "No matching spaces or views. Press Esc to close.");
    dict.set("command_palette.close", "Close (Esc)");

    dict.set("mobile.filter_spaces", "Filter spaces…");
    dict.set("mobile.no_match", "No spaces match.");

    // Kanban / Board view (header + section labels)
    dict.set("kanban.board_header", "Launch Board");
    dict.set("kanban.board_title", "Board");
    dict.set(
        "kanban.board_hint",
        "Drag cards across lists to queue cx.flow.move; projection refresh promotes seed data when the server view endpoint is available.",
    );

    // Directory view (tabs share the existing `directory.tab.*` keys).
    dict.set("directory.org_empty_body", "No organizations found. Try a search.");
    dict.set("directory.actors_empty_body", "No actors found. Try a search.");

    // Recovery view (top-level section headers)
    dict.set("recovery.title", "Recovery");
    dict.set("recovery.vault_section", "Encrypted Cloud Vault");
    dict.set("recovery.recovery_key_section", "Recovery Key");
    dict.set("recovery.social_section", "Social Recovery");

    // Space-admin view (section labels)
    dict.set("space_admin.title", "Space Admin");
    dict.set("space_admin.governance", "Governance");
    dict.set("space_admin.devices", "Devices");

    // Chat / Discussion view (panel headers + key buttons; reuse common.* for
    // generic verbs like Save/Cancel/Retry/Edit/Confirm).
    dict.set("chat.discussions_header", "Discussions");
    dict.set("chat.users_header", "Users");
    dict.set("chat.settings_header", "Settings");
    dict.set("chat.new_discussion", "New discussion");
    dict.set("chat.hide_list", "Hide discussion list");
    dict.set("chat.label.title", "Title");
    dict.set("chat.label.summary", "Summary");
    dict.set("chat.label.users", "Users");
    dict.set("chat.button.create", "Create");
    dict.set("chat.button.reply", "Reply");
    dict.set("chat.button.react", "React");
    dict.set("chat.button.redact", "Redact");
    dict.set("chat.you_badge", "You");

    // Notifications panel (group tabs + toolbar tooltips)
    dict.set("notifications.group.all", "All");
    dict.set("notifications.group.space", "Space");
    dict.set("notifications.group.type", "Type");
    dict.set("notifications.group.time", "Time");
    dict.set("notifications.tooltip.mark_all_read", "Mark all read");
    dict.set("notifications.tooltip.show_archived", "Show archived");
    dict.set("notifications.tooltip.hide_archived", "Hide archived");
    dict.set("notifications.tooltip.refresh", "Refresh notifications");
    dict.set("notifications.settings_card", "Notification settings");
    dict.set("notifications.settings_card_hint", "managed in Settings");
    dict.set(
        "notifications.settings_card_body",
        "Notification rules, muted spaces, and push delivery preferences now live in Settings.",
    );
    dict.set("notifications.settings_card_open", "Open settings");
    dict.set("notifications.empty_body", "No server-derived notifications loaded yet.");
    dict.set(
        "notifications.filtered_body",
        "All loaded notifications are currently hidden by archive, type, or per-space mute rules.",
    );

    // Verify Device (cross-signing / SAS)
    dict.set("verify_device.title", "Device Verification");
    dict.set("verify_device.choose_method", "choose method");
    dict.set("verify_device.qr_code", "QR Code");
    dict.set("verify_device.sas_emoji", "SAS (Emoji)");
    dict.set("verify_device.qr_section", "QR Verification");
    dict.set("verify_device.qr_section_hint", "scan or display");
    dict.set("verify_device.sas_section", "SAS Verification");
    dict.set("verify_device.sas_section_hint", "emoji comparison");
    dict.set("verify_device.target_device_id", "Target Device ID");
    dict.set("verify_device.target_device_placeholder", "Device ID to verify");
    dict.set("verify_device.generate_qr", "Generate QR Data");
    dict.set("verify_device.start_sas", "Start SAS Verification");
    dict.set("verify_device.short_auth_string", "Short Authentication String");

    dict
}

/// Build Chinese translation dictionary.
pub fn chinese_translations() -> TranslationDict {
    let mut dict = TranslationDict::new(Locale::Zh);

    dict.set("app.title", "yougen");
    dict.set("nav.dashboard", "仪表盘");
    dict.set("nav.timeline", "时间线");
    dict.set("nav.chat", "聊天");
    dict.set("nav.forum", "论坛");
    dict.set("nav.directory", "目录");
    dict.set("nav.notifications", "通知");
    dict.set("nav.settings", "设置");
    dict.set("nav.login", "登录");
    dict.set("nav.audit", "审计");
    dict.set("nav.devices", "设备");

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
    dict.set("topbar.search_placeholder", "跳转到空间、视图或操作…");
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
    dict.set("dashboard.spaces_label", "空间");
    dict.set("dashboard.spaces_delta_search", "搜索或加入空间");
    dict.set("dashboard.spaces_delta_signin", "登录后加载空间");
    dict.set("dashboard.current_space", "当前空间");
    dict.set("dashboard.workspace_setup", "工作区设置");
    dict.set("dashboard.workspace_setup_delta", "创建第一个空间与初始策略");
    dict.set("dashboard.onboarding", "引导");
    dict.set("dashboard.onboarding_steps", "4 步");
    dict.set("dashboard.onboarding_delta", "身份、设备与恢复方案");
    dict.set("dashboard.recent_spaces", "最近空间");
    dict.set("dashboard.no_spaces", "暂无空间");
    dict.set("dashboard.no_spaces_help", "服务器尚未返回空间列表。");
    dict.set("dashboard.no_session_help", "客户端不会展示占位空间。");

    dict.set("notifications.archived", "显示已归档");
    dict.set("notifications.mark_all_read", "全部标记已读");
    dict.set("notifications.empty_state", "暂无通知。");

    dict.set("composer.send", "发送");
    dict.set("composer.encrypted_toggle", "本地加密");
    dict.set("composer.plaintext_warning", "明文消息对所配置的服务器可见。");

    dict.set("command_palette.spaces", "空间");
    dict.set("command_palette.jump_to", "跳转到");
    dict.set("command_palette.empty", "未找到匹配的空间或视图。按 Esc 关闭。");
    dict.set("command_palette.close", "关闭 (Esc)");

    dict.set("mobile.filter_spaces", "筛选空间…");
    dict.set("mobile.no_match", "未找到匹配空间。");

    // Kanban / Board view
    dict.set("kanban.board_header", "启动看板");
    dict.set("kanban.board_title", "看板");
    dict.set(
        "kanban.board_hint",
        "拖动卡片到不同列以排队 cx.flow.move 写入；服务端 view 接口可用时刷新会替换种子数据。",
    );

    // Directory view
    dict.set("directory.org_empty_body", "未找到组织，可尝试搜索。");
    dict.set("directory.actors_empty_body", "未找到 actor，可尝试搜索。");

    // Recovery view
    dict.set("recovery.title", "恢复");
    dict.set("recovery.vault_section", "加密云保险箱");
    dict.set("recovery.recovery_key_section", "恢复密钥");
    dict.set("recovery.social_section", "社交恢复");

    // Space-admin view
    dict.set("space_admin.title", "Space 管理");
    dict.set("space_admin.governance", "治理");
    dict.set("space_admin.devices", "设备");

    // Chat / Discussion view
    dict.set("chat.discussions_header", "讨论");
    dict.set("chat.users_header", "用户");
    dict.set("chat.settings_header", "设置");
    dict.set("chat.new_discussion", "新建讨论");
    dict.set("chat.hide_list", "隐藏讨论列表");
    dict.set("chat.label.title", "标题");
    dict.set("chat.label.summary", "概述");
    dict.set("chat.label.users", "用户");
    dict.set("chat.button.create", "创建");
    dict.set("chat.button.reply", "回复");
    dict.set("chat.button.react", "回应");
    dict.set("chat.button.redact", "撤回");
    dict.set("chat.you_badge", "我");

    // Notifications panel
    dict.set("notifications.group.all", "全部");
    dict.set("notifications.group.space", "按空间");
    dict.set("notifications.group.type", "按类型");
    dict.set("notifications.group.time", "按时间");
    dict.set("notifications.tooltip.mark_all_read", "全部标为已读");
    dict.set("notifications.tooltip.show_archived", "显示已归档");
    dict.set("notifications.tooltip.hide_archived", "隐藏已归档");
    dict.set("notifications.tooltip.refresh", "刷新通知");
    dict.set("notifications.settings_card", "通知设置");
    dict.set("notifications.settings_card_hint", "在「设置」中管理");
    dict.set(
        "notifications.settings_card_body",
        "通知规则、静音空间、推送偏好现在统一在「设置」中管理。",
    );
    dict.set("notifications.settings_card_open", "打开设置");
    dict.set("notifications.empty_body", "尚未加载到任何服务端通知。");
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

    dict
}

/// Build Arabic translation dictionary.
pub fn arabic_translations() -> TranslationDict {
    let mut dict = TranslationDict::new(Locale::Ar);

    dict.set("app.title", "yougen");
    dict.set("nav.dashboard", "لوحة التحكم");
    dict.set("nav.timeline", "الخط الزمني");
    dict.set("nav.chat", "الدردشة");
    dict.set("nav.forum", "المنتدى");
    dict.set("nav.directory", "الدليل");
    dict.set("nav.notifications", "الإشعارات");
    dict.set("nav.settings", "الإعدادات");
    dict.set("nav.login", "تسجيل الدخول");
    dict.set("nav.audit", "التدقيق");
    dict.set("nav.devices", "الأجهزة");

    dict.set("settings.title", "الإعدادات");
    dict.set("settings.theme", "المظهر");
    dict.set("settings.language", "اللغة");
    dict.set("settings.light", "فاتح");
    dict.set("settings.dark", "داكن");
    dict.set("settings.system", "النظام");

    dict.set("common.loading", "جار التحميل...");
    dict.set("common.error", "خطأ");
    dict.set("common.retry", "إعادة المحاولة");
    dict.set("common.online", "متصل");
    dict.set("common.offline", "غير متصل");
    dict.set("common.reconnecting", "إعادة الاتصال");

    dict
}

/// Initialize the i18n system with default translations.
pub fn init_i18n() -> I18nSignal {
    init_i18n_with_locale(Locale::En)
}

/// Initialize i18n preloaded with a specific locale.
pub fn init_i18n_with_locale(locale: Locale) -> I18nSignal {
    let mut dicts = HashMap::new();
    let en = english_translations();
    let zh = chinese_translations();
    let ar = arabic_translations();
    dicts.insert("en".to_owned(), en);
    dicts.insert("zh".to_owned(), zh);
    dicts.insert("ar".to_owned(), ar);
    Signal::new((locale, dicts))
}

/// Switch the active locale on an existing signal without rebuilding the
/// translation tables. Call this from the Settings language picker.
pub fn set_locale(signal: &mut I18nSignal, locale: Locale) {
    if signal.read().0 == locale {
        return;
    }
    let dicts = signal.read().1.clone();
    signal.set((locale, dicts));
}

/// Convenience: pull the current i18n signal from Dioxus context and
/// translate `key`. Views call this once they have been wrapped in a
/// `provide_context(init_i18n_with_locale(...))` ancestor — currently
/// `WorkspaceView`. Falls back to the key itself when no context is
/// installed (e.g. unit tests outside Dioxus runtime).
pub fn tr(key: &str) -> String {
    match try_consume_context::<I18nSignal>() {
        Some(signal) => t(&signal, key),
        None => key.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_from_code() {
        assert_eq!(Locale::from_code("en"), Locale::En);
        assert_eq!(Locale::from_code("zh"), Locale::Zh);
        assert_eq!(Locale::from_code("zh-CN"), Locale::Zh);
        assert_eq!(Locale::from_code("ar"), Locale::Ar);
        assert_eq!(Locale::from_code("fr"), Locale::En); // fallback
    }

    #[test]
    fn locale_direction_matches_layout_expectations() {
        assert_eq!(Locale::En.direction(), TextDirection::Ltr);
        assert_eq!(Locale::Zh.direction(), TextDirection::Ltr);
        assert_eq!(Locale::Ar.direction(), TextDirection::Rtl);
        assert_eq!(Locale::Ar.direction().as_str(), "rtl");
    }

    #[test]
    fn translation_lookup_fallback() {
        let mut dicts = HashMap::new();
        let en = english_translations();
        let zh = chinese_translations();
        dicts.insert("en".to_owned(), en);
        dicts.insert("zh".to_owned(), zh);

        // Chinese translation exists
        assert_eq!(translate(Locale::Zh, &dicts, "login.server"), "服务器");

        // Fallback to English for missing Chinese key
        let partial_dicts = {
            let mut partial = HashMap::new();
            let mut zh_partial = TranslationDict::new(Locale::Zh);
            zh_partial.set("login.server", "服务器");
            partial.insert("en".to_owned(), english_translations());
            partial.insert("zh".to_owned(), zh_partial);
            partial
        };
        assert_eq!(
            translate(Locale::Zh, &partial_dicts, "login.passkey"),
            "Passkey Login"
        );

        // Fallback to key itself when not found anywhere
        assert_eq!(
            translate(Locale::En, &HashMap::new(), "nonexistent.key"),
            "nonexistent.key"
        );
    }

    #[test]
    fn locale_formatters_are_stable() {
        let timestamp = DateTime::parse_from_rfc3339("2026-04-29T07:08:09Z")
            .unwrap()
            .with_timezone(&Utc);

        assert_eq!(
            format_datetime(Locale::En, timestamp),
            "Apr 29, 2026 07:08 UTC"
        );
        assert_eq!(
            format_datetime(Locale::Zh, timestamp),
            "2026年04月29日 07:08 UTC"
        );
        assert_eq!(
            format_datetime(Locale::Ar, timestamp),
            "2026/04/29 07:08 UTC"
        );
        assert_eq!(format_number(Locale::En, 1234567), "1,234,567");
        assert_eq!(format_number(Locale::Zh, 1234567), "1 234 567");
    }

    #[test]
    fn translation_completeness_reports_missing_keys() {
        let en = english_translations();
        let zh = chinese_translations();
        let report = translation_completeness(&en, &zh);
        assert_eq!(report.locale, Locale::Zh);
        assert_eq!(report.total_keys, en.strings.len());
        assert!(report.missing_count() > 0);
        assert!(
            report
                .missing_keys
                .contains(&"directory.applet.metadata".to_owned())
        );

        let complete = translation_completeness(&en, &en);
        assert!(complete.is_complete());
    }
}
