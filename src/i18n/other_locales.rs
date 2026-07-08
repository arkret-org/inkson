//! Secondary-locale dictionaries (Arabic, Spanish, Japanese, French).
//! These are starter sets that intentionally cover only the highest-
//! visibility keys and fall through to English via `translate_chain`.

use super::{Locale, TranslationDict};

/// Build Arabic translation dictionary.
pub fn arabic_translations() -> TranslationDict {
    let mut dict = TranslationDict::new(Locale::Ar);

    dict.set("app.title", "inkson");
    dict.set("nav.dashboard", "Home");
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

/// Phase D.2 #8: Spanish — covers the highest-visibility nav / common
/// keys. Anything not listed falls through to English via the
/// `translate_chain` fallback.
pub fn spanish_translations() -> TranslationDict {
    let mut dict = TranslationDict::new(Locale::Es);
    dict.set("app.title", "inkson");
    dict.set("nav.dashboard", "Home");
    dict.set("nav.chat", "Chat");
    dict.set("nav.forum", "Foro");
    dict.set("nav.directory", "Directorio");
    dict.set("nav.notifications", "Notificaciones");
    dict.set("nav.settings", "Ajustes");
    dict.set("nav.login", "Iniciar sesión");
    dict.set("nav.audit", "Auditoría");
    dict.set("nav.devices", "Dispositivos");
    dict.set("common.loading", "Cargando...");
    dict.set("common.error", "Error");
    dict.set("common.retry", "Reintentar");
    dict.set("common.close", "Cerrar");
    dict.set("common.confirm", "Confirmar");
    dict.set("common.cancel", "Cancelar");
    dict.set("common.save", "Guardar");
    dict.set("common.delete", "Eliminar");
    dict.set("common.edit", "Editar");
    dict.set("common.send", "Enviar");
    dict.set("common.refresh", "Actualizar");
    dict.set("common.back", "Atrás");
    dict.set("common.next", "Siguiente");
    dict.set("common.online", "en línea");
    dict.set("common.offline", "sin conexión");
    dict.set("common.reconnecting", "reconectando");
    dict.set("settings.title", "Ajustes");
    dict.set("settings.theme", "Tema");
    dict.set("settings.language", "Idioma");
    dict.set("settings.light", "Claro");
    dict.set("settings.dark", "Oscuro");
    dict.set("settings.system", "Sistema");
    dict.set("login.server", "Servidor");
    dict.set("login.continue", "Continuar");
    dict
}

/// Phase D.2 #8: Japanese — nav / common starter set.
pub fn japanese_translations() -> TranslationDict {
    let mut dict = TranslationDict::new(Locale::Ja);
    dict.set("app.title", "inkson");
    dict.set("nav.dashboard", "Home");
    dict.set("nav.chat", "チャット");
    dict.set("nav.forum", "フォーラム");
    dict.set("nav.directory", "ディレクトリ");
    dict.set("nav.notifications", "通知");
    dict.set("nav.settings", "設定");
    dict.set("nav.login", "ログイン");
    dict.set("nav.audit", "監査");
    dict.set("nav.devices", "デバイス");
    dict.set("common.loading", "読み込み中...");
    dict.set("common.error", "エラー");
    dict.set("common.retry", "再試行");
    dict.set("common.close", "閉じる");
    dict.set("common.confirm", "確認");
    dict.set("common.cancel", "キャンセル");
    dict.set("common.save", "保存");
    dict.set("common.delete", "削除");
    dict.set("common.edit", "編集");
    dict.set("common.send", "送信");
    dict.set("common.refresh", "更新");
    dict.set("common.back", "戻る");
    dict.set("common.next", "次へ");
    dict.set("common.online", "オンライン");
    dict.set("common.offline", "オフライン");
    dict.set("common.reconnecting", "再接続中");
    dict.set("settings.title", "設定");
    dict.set("settings.theme", "テーマ");
    dict.set("settings.language", "言語");
    dict.set("settings.light", "ライト");
    dict.set("settings.dark", "ダーク");
    dict.set("settings.system", "システム");
    dict.set("login.server", "サーバー");
    dict.set("login.continue", "続行");
    dict
}

/// Phase D.2 #8: French — nav / common starter set.
pub fn french_translations() -> TranslationDict {
    let mut dict = TranslationDict::new(Locale::Fr);
    dict.set("app.title", "inkson");
    dict.set("nav.dashboard", "Home");
    dict.set("nav.chat", "Discussion");
    dict.set("nav.forum", "Forum");
    dict.set("nav.directory", "Annuaire");
    dict.set("nav.notifications", "Notifications");
    dict.set("nav.settings", "Paramètres");
    dict.set("nav.login", "Connexion");
    dict.set("nav.audit", "Audit");
    dict.set("nav.devices", "Appareils");
    dict.set("common.loading", "Chargement...");
    dict.set("common.error", "Erreur");
    dict.set("common.retry", "Réessayer");
    dict.set("common.close", "Fermer");
    dict.set("common.confirm", "Confirmer");
    dict.set("common.cancel", "Annuler");
    dict.set("common.save", "Enregistrer");
    dict.set("common.delete", "Supprimer");
    dict.set("common.edit", "Modifier");
    dict.set("common.send", "Envoyer");
    dict.set("common.refresh", "Actualiser");
    dict.set("common.back", "Retour");
    dict.set("common.next", "Suivant");
    dict.set("common.online", "en ligne");
    dict.set("common.offline", "hors ligne");
    dict.set("common.reconnecting", "reconnexion");
    dict.set("settings.title", "Paramètres");
    dict.set("settings.theme", "Thème");
    dict.set("settings.language", "Langue");
    dict.set("settings.light", "Clair");
    dict.set("settings.dark", "Sombre");
    dict.set("settings.system", "Système");
    dict.set("login.server", "Serveur");
    dict.set("login.continue", "Continuer");
    dict
}
