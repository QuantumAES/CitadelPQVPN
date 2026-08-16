//! L-9 (аудит-4), вторая половина: **подпись образа клиента пайпа**.
//!
//! Служба уже требует, чтобы подключившийся процесс был образом из её install-dir (W3,
//! `plan::same_dir`). Это отсекает малварь медиум-integrity: в `%ProgramFiles%\CitadelPQVPN` пишет
//! только админ. Остаётся класс «в каталог службы положили ЧУЖОЙ подписанный бинарь» (кривая
//! установка не в Program Files, ACL, ослабленный админом при переносе каталога, сторонний
//! инсталлятор) — здесь и работает проверка Authenticode: образ клиента обязан быть подписан и
//! ТЕМ ЖЕ издателем, что сама служба.
//!
//! **Политика само-калибрующаяся.** Требовать подпись имеет смысл только у подписанной сборки:
//! собранный из исходников (или dev-)`citadel-svc.exe` не подписан ничем, и требование сломало бы
//! ему собственное приложение. Поэтому режим определяется по ОБРАЗУ САМОЙ СЛУЖБЫ: подпись службы
//! проверяется и её издатель извлекается тем же кодом, что потом применяется к клиенту. Не вышло —
//! проверка выключается с явной строкой в журнале (остаётся install-dir), вышло — клиент обязан
//! пройти ту же проверку с тем же издателем. Так неподписанная сборка работает как раньше, а
//! ошибка в этом самом коде не превращается в «приложение не может подключиться к своей службе»:
//! она симметрично отключает режим, а не запирает пользователя.
//!
//! **Отзыв не проверяем** (`WTD_REVOKE_NONE` + `WTD_CACHE_ONLY_URL_RETRIEVAL`): проверка идёт на
//! потоке-акцепторе пайпа, а поход в CRL/OCSP по сети может занять секунды и подвесить подключение
//! приложения — в том числе когда сети нет вовсе (kill-switch армирован). Отозванная подпись при
//! этом всё ещё должна лежать в admin-only каталоге, то есть противник уже админ.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CertGetNameStringW,
    CryptMsgClose, CryptMsgGetParam, CryptQueryObject, CERT_CONTEXT, CERT_FIND_SUBJECT_CERT,
    CERT_INFO, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
    CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO,
    CMSG_SIGNER_INFO_PARAM, HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
use windows_sys::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_SAFER_FLAG,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

/// Режим проверки подписи клиента. Вычисляется один раз по образу самой службы.
pub enum Policy {
    /// Служба подписана: клиент обязан быть подписан тем же издателем.
    Enforce {
        /// Отображаемое имя издателя (`CERT_NAME_SIMPLE_DISPLAY_TYPE`) образа службы.
        subject: String,
    },
    /// Служба не подписана (или подпись не читается) — проверка клиента выключена, работает W3.
    Off {
        /// Почему выключена (уходит в журнал службы при старте).
        why: String,
    },
}

/// Политика проверки подписи для этого процесса службы (вычисляется однажды, лениво).
pub fn policy() -> &'static Policy {
    static P: OnceLock<Policy> = OnceLock::new();
    P.get_or_init(|| match own_image().and_then(|p| signer_of(&p)) {
        Ok(subject) => Policy::Enforce { subject },
        Err(e) => Policy::Off { why: format!("{e:#}") },
    })
}

/// Строка о выбранном режиме для баннера службы.
pub fn policy_banner() -> String {
    match policy() {
        Policy::Enforce { subject } => {
            format!("L-9: подпись клиента проверяется, издатель службы — {subject:?}")
        }
        Policy::Off { why } => {
            format!("L-9: подпись клиента НЕ проверяется (образ службы не подписан: {why}); остаётся W3 (install-dir)")
        }
    }
}

/// Проверить образ клиента пайпа по действующей политике.
pub fn check_client_image(path: &Path) -> anyhow::Result<()> {
    let Policy::Enforce { subject } = policy() else {
        return Ok(()); // неподписанная сборка: режим выключен, причина уже в журнале
    };
    let client = signer_of(path)?;
    if &client != subject {
        anyhow::bail!(
            "L-9: издатель образа клиента {client:?} ≠ издатель службы {subject:?} — \
             в каталоге службы лежит чужой подписанный бинарь"
        );
    }
    Ok(())
}

/// Полный путь образа самой службы.
fn own_image() -> anyhow::Result<PathBuf> {
    std::env::current_exe().map_err(|e| anyhow::anyhow!("current_exe: {e}"))
}

/// Проверить цепочку подписи файла и вернуть отображаемое имя издателя. Обе операции вместе:
/// имя без валидной цепочки ничего не значит (его можно вписать в самоподписанный сертификат).
fn signer_of(path: &Path) -> anyhow::Result<String> {
    verify_trust(path)?;
    signer_display_name(path)
}

/// `WinVerifyTrust` с политикой `WINTRUST_ACTION_GENERIC_VERIFY_V2`: подпись есть, цепочка ведёт к
/// доверенному корню, файл не изменён после подписания.
fn verify_trust(path: &Path) -> anyhow::Result<()> {
    let wide_path = wide(path);
    // SAFETY: обе структуры — zeroed с выставленным cbStruct; `wide_path` и `file` живут до конца
    // функции (WinVerifyTrust читает их по указателю); state-данные закрываются вторым вызовом с
    // WTD_STATEACTION_CLOSE — без него утекает контекст проверки.
    unsafe {
        let mut file: WINTRUST_FILE_INFO = std::mem::zeroed();
        file.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        file.pcwszFilePath = wide_path.as_ptr();

        let mut data: WINTRUST_DATA = std::mem::zeroed();
        data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;
        data.Anonymous.pFile = &mut file;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let rc = WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast::<c_void>(),
        );
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast::<c_void>(),
        );
        if rc != 0 {
            anyhow::bail!("WinVerifyTrust({path:?}) → 0x{:08X}", rc as u32);
        }
    }
    Ok(())
}

/// Отображаемое имя издателя из встроенной PKCS#7-подписи файла.
///
/// Путь стандартный: `CryptQueryObject` (достать store+сообщение из образа) → `CMSG_SIGNER_INFO`
/// (издатель + серийный номер подписанта) → найти по ним сам сертификат в store → `CertGetNameStringW`.
fn signer_display_name(path: &Path) -> anyhow::Result<String> {
    let wide_path = wide(path);
    let mut store: HCERTSTORE = std::ptr::null_mut();
    let mut msg: *mut c_void = std::ptr::null_mut();

    // SAFETY: все хэндлы, полученные CryptQueryObject, закрываются на КАЖДОМ выходе (в т.ч. по
    // ошибке) — для этого тело обёрнуто в замыкание, а очистка идёт после него. Буферы выделяются
    // по размеру, который вернул сам API; CMSG_SIGNER_INFO читается из выровненного по 8 буфера.
    let out = unsafe {
        if CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide_path.as_ptr().cast::<c_void>(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut store,
            &mut msg,
            std::ptr::null_mut(),
        ) == 0
        {
            anyhow::bail!("CryptQueryObject({path:?}): подписи нет или она не читается");
        }

        let res = (|| -> anyhow::Result<String> {
            // Размер CMSG_SIGNER_INFO, затем сам блок (выравнивание — Vec<u64>, иначе чтение полей
            // структуры из Vec<u8> было бы невыровненным).
            let mut need: u32 = 0;
            if CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, std::ptr::null_mut(), &mut need) == 0
                || need == 0
            {
                anyhow::bail!("CryptMsgGetParam(размер CMSG_SIGNER_INFO)");
            }
            let mut buf: Vec<u64> = vec![0; need.div_ceil(8) as usize];
            if CryptMsgGetParam(
                msg,
                CMSG_SIGNER_INFO_PARAM,
                0,
                buf.as_mut_ptr().cast::<c_void>(),
                &mut need,
            ) == 0
            {
                anyhow::bail!("CryptMsgGetParam(CMSG_SIGNER_INFO)");
            }
            let signer: *const CMSG_SIGNER_INFO = buf.as_ptr().cast();

            // Сертификат подписанта ищем в store по паре (издатель, серийный номер).
            let mut want: CERT_INFO = std::mem::zeroed();
            want.Issuer = (*signer).Issuer;
            want.SerialNumber = (*signer).SerialNumber;
            let ctx: *const CERT_CONTEXT = CertFindCertificateInStore(
                store,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_SUBJECT_CERT,
                (&want as *const CERT_INFO).cast::<c_void>(),
                std::ptr::null(),
            );
            if ctx.is_null() {
                anyhow::bail!("сертификат подписанта не найден в образе");
            }
            let name = cert_display_name(ctx);
            CertFreeCertificateContext(ctx);
            name
        })();

        if !msg.is_null() {
            CryptMsgClose(msg);
        }
        if !store.is_null() {
            CertCloseStore(store, 0);
        }
        res
    };
    out
}

/// `CERT_NAME_SIMPLE_DISPLAY_TYPE` сертификата — то, что Проводник показывает как «Издатель».
///
/// # Safety
/// `ctx` — валидный контекст сертификата, живой на время вызова.
unsafe fn cert_display_name(ctx: *const CERT_CONTEXT) -> anyhow::Result<String> {
    let len = CertGetNameStringW(
        ctx,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        std::ptr::null(),
        std::ptr::null_mut(),
        0,
    );
    // API возвращает длину В СИМВОЛАХ, включая завершающий ноль: 1 = пустое имя.
    if len <= 1 {
        anyhow::bail!("у сертификата подписанта пустое отображаемое имя");
    }
    let mut buf = vec![0u16; len as usize];
    let got = CertGetNameStringW(
        ctx,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        std::ptr::null(),
        buf.as_mut_ptr(),
        len,
    );
    if got <= 1 {
        anyhow::bail!("CertGetNameStringW вернул пустое имя");
    }
    Ok(String::from_utf16_lossy(&buf[..got as usize - 1]))
}

/// Путь → UTF-16 с завершающим нулём (WinAPI-строка).
fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}
