use crate::jar::{ScanResult, TrustInfo};

fn norm_id(s: &str) -> String {
    s.chars()
        .filter(|&c| c != '_' && c != '-' && c != ' ' && c != '.')
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn key_allowed(k: &str, l: &[String]) -> bool {
    l.iter().any(|x| x == k)
}

fn any_starts(names: &[String], pfx: &str) -> bool {
    names.iter().any(|n| n.starts_with(pfx))
}

fn has_class(names: &[String], full: &str) -> bool {
    names.iter().any(|n| n == full)
}

const MIXIN_CORE: [&str; 3] = [
    "org/spongepowered/asm/launch/MixinBootstrap",
    "org/spongepowered/asm/mixin/Mixins",
    "org/spongepowered/asm/service/MixinService",
];
const MIXIN_PKGS: [&str; 10] = [
    "org/spongepowered/asm/",
    "org/spongepowered/tools/",
    "org/spongepowered/include/",
    "org/spongepowered/libraries/",
    "org/objectweb/asm/",
    "com/llamalad7/mixinextras/",
    "com/google/",
    "org/apache/logging/log4j/",
    "com/sun/jna/",
    "org/apache/commons/",
];

fn is_mixin_library(names: &[String]) -> bool {
    if names.len() < 50 {
        return false; // gerçek kütüphane yüzlerce sınıf taşır
    }
    let core = MIXIN_CORE.iter().filter(|c| has_class(names, c)).count();
    if core < 2 {
        return false;
    }
    for n in names {
        if !MIXIN_PKGS.iter().any(|p| n.starts_with(p)) {
            return false; // kütüphane dışı tek bir sınıf bile varsa altyapı sayılmaz
        }
    }
    true
}

// UniMixins (1.7.10 / 1.12.2 Mixin yükleyicisi): SpongePowered Mixin kütüphanesini Forge'un eski
// sürümlerine taşıyan modüller. Kütüphaneye ek olarak YALNIZCA şu yükleyici paketlerini taşır.
const UNIMIXINS_ROOT: &str = "io/github/legacymoddingmc/unimixins/";
const UNIMIXINS_PKGS: [&str; 8] = [
    UNIMIXINS_ROOT,
    "com/gtnewhorizon/gtnhmixins/",
    "com/gtnewhorizon/mixinextras/", // eski GTNH MixinExtras uyumluluk kopyası (.klass olarak saklanır)
    "ru/timeconqueror/spongemixins/",
    "com/falsepattern/gasstation/",
    "makamys/mixingasm/",
    "io/github/tox1cozz/mixinbooterlegacy/",
    "io/github/tox1cozz/mixinextras/",
];

fn is_unimixins(names: &[String], agent_cls: &str) -> bool {
    if names.len() < 50 {
        return false;
    }
    let core = MIXIN_CORE.iter().filter(|c| has_class(names, c)).count();
    if core < 2 || !any_starts(names, UNIMIXINS_ROOT) {
        return false;
    }
    let agent = agent_cls.replace('.', "/");
    if !agent.is_empty() && agent != "org/spongepowered/tools/agent/MixinAgent" {
        return false; // ajan varsa Mixin kütüphanesinin KENDİ ajanı olmalı
    }
    for n in names {
        if !MIXIN_PKGS.iter().any(|p| n.starts_with(p)) && !UNIMIXINS_PKGS.iter().any(|p| n.starts_with(p)) {
            return false; // yükleyici dışı tek bir sınıf bile varsa altyapı sayılmaz
        }
    }
    true
}

struct KnownGood {
    id: &'static str,
    pkg: &'static str,
    label: &'static str,
    why: &'static str,
    keys: &'static str,
}

const KNOWN_GOOD: [KnownGood; 8] = [
    KnownGood {
        id: "cofh_core",
        pkg: "cofh/",
        label: "CoFH Core (kütüphane modu)",
        why: "Modun kendi geri tepme / blok kırma mekaniği için ilgili istemci metotlarına müdahale eder; \
              hile modülü değil, mod paketinin alt yapısıdır.",
        keys: "velocity,velocity_player,break_free",
    },
    KnownGood {
        id: "crash_assistant",
        pkg: "dev/kostromdan/mods/crash_assistant/",
        label: "Crash Assistant (çökme raporlayıcı)",
        why: "Oyun çökmelerini yakalayıp raporlamak için Java agent kullanır; oyuncuya oyun içi avantaj sağlamaz.",
        keys: "java_agent,injector",
    },
    KnownGood {
        id: "starterkit",
        pkg: "com/natamus/starterkit/",
        label: "Starter Kit (başlangıç eşyası modu)",
        why: "Başlangıç setini verirken envanter slotlarını kodla boşaltır; oyuncuya hile avantaji sağlamaz.",
        keys: "drop_all",
    },
    KnownGood {
        id: "securitycraft",
        pkg: "net/geforcemods/securitycraft/",
        label: "SecurityCraft (güvenlik blogu modu)",
        why: "Kamera blogu / gözetleme için nişangah hesabina müdahale eder; menzil uzatmaz.",
        keys: "crosshair_value_mod",
    },
    KnownGood {
        id: "shouldersurfing",
        pkg: "com/github/exopandora/shouldersurfing/",
        label: "Shoulder Surfing Reloaded (omuz kamerası)",
        why: "Üçüncü şahıs omuz kamerası için nişangah/bakış hesabina müdahale eder; menzil uzatmaz.",
        keys: "crosshair_value_mod",
    },
    KnownGood {
        id: "",
        pkg: "com/sklauncher/",
        label: "SKLauncher (3. parti Minecraft başlatıcısı)",
        why: "Bir Minecraft başlatıcısıdır; oyunu başlatmak için kendi agent'ini kullanır. Hile modülü değildir, \
              ancak resmi Mojang başlatıcısı da değildir.",
        keys: "java_agent,injector,hidden_loader",
    },
    KnownGood {
        id: "bettercombat",
        pkg: "net/bettercombat/",
        label: "Better Combat (savaş sistemi modu)",
        why: "Silah kombo / savurma sistemini kurar: silaha göre menzil, basılı tutunca savurma ve savurma \
              yayındaki hedefleri bulma. İstemci tarafı yalnızca sunucuda da Better Combat kuruluysa ve sunucu \
              ayarlarını gönderdiyse açılır; vuruş menzili ve hedefler sunucuda yeniden doğrulanır. Sunucusuz \
              hiçbir etkisi yoktur.",
        keys: "triggerbot,autoclicker,attack_through,reach,reach_player,crosshair_value_mod",
    },
    KnownGood {
        id: "pehkui",
        pkg: "virtuoel/pehkui/",
        label: "Pehkui (varlık boyutu / ölçek modu)",
        why: "Varlık boyutunu ölçekler; menzil, adım yüksekliği, vuruş kutusu, itme ve geri tepme değerlerini \
              ölçekle çarpar. Ölçek varsayılan 1.0'dır ve yalnızca sunucu (/scale, OP yetkisi) değiştirir; \
              ölçek 1.0 iken değerler aynen kalır.",
        keys: "reach,reach_player,crosshair_value_mod,step,hitboxes,velocity,velocity_player,anti_push",
    },
];

pub fn classify_trusted(mod_id: &str, class_names: &[String], agent_cls: &str) -> TrustInfo {
    let mut t = TrustInfo::default();
    if is_mixin_library(class_names) {
        t.infra = true;
        t.label = "Mixin kütüphanesi (SpongePowered)".to_string();
        t.note = "Bu dosya mod yükleyicinin KENDİ parçası olan Mixin kütüphanesidir (Fabric / Forge / NeoForge \
                  bunu olduğu gibi dağıtır; her modlu kurulumda bulunur). Bir Java agent olması ve çalışan oyunun \
                  sınıflarını yeniden yazması bu kütüphanenin normal işlevidir - modlar oyuna bu şekilde eklenir. \
                  Doğrulama içerikten yapıldı: çekirdek Mixin sınıfları var ve arşivdeki TÜM sınıflar kütüphanenin \
                  kendi paketlerinde. Şüphelenilmesi gereken şey kütüphane değil, bu kütüphaneyle Minecraft'in \
                  vuruş / hareket / görüş koduna müdahale eden MODun kendi mixin sınıflarıdır."
            .to_string();
        return t;
    }
    if is_unimixins(class_names, agent_cls) {
        t.infra = true;
        t.label = "UniMixins (eski Forge sürümleri için Mixin yükleyicisi)".to_string();
        t.note = "Bu dosya Mixin kütüphanesinin eski Forge sürümlerine (1.7.10 / 1.12.2) uyarlanmış dağıtımıdır \
                  (UniMixins: Mixin, SpongeMixins, MixinBooterLegacy, GTNHMixins, GasStation, Mixingasm, \
                  MixinExtras). Java agent olması Mixin kütüphanesinin kendi ajanıdır (MixinAgent). Doğrulama \
                  içerikten yapıldı: çekirdek Mixin sınıfları var ve arşivdeki TÜM sınıflar ya kütüphanenin ya da \
                  UniMixins yükleyici modüllerinin paketlerinde; bu modüllerin mixinleri yalnızca mod yükleyicisine \
                  (FML) dokunur, vuruş / hareket / görüş koduna değil."
            .to_string();
        return t;
    }
    let nid = norm_id(mod_id);
    for k in KNOWN_GOOD.iter() {
        if !any_starts(class_names, k.pkg) {
            continue; // paket kanıtı ZORUNLU
        }
        if !k.id.is_empty() && !nid.is_empty() && nid != norm_id(k.id) {
            continue; // kimlik bildirilmişse eşleşmeli
        }
        t.known_good = true;
        t.label = k.label.to_string();
        t.note = k.why.to_string();
        for s in k.keys.split(',') {
            t.allow_keys.push(s.to_string());
        }
        return t;
    }
    let _ = agent_cls;
    t
}

pub fn apply_known_good(res: &mut ScanResult, t: &TrustInfo) {
    if !t.known_good || t.allow_keys.is_empty() {
        return;
    }
    for f in res.findings.iter_mut() {
        if f.category == "BILGI" {
            continue;
        }
        if !key_allowed(&f.key, &t.allow_keys) {
            continue; // izin verilmeyen bulgu AYNEN kalır
        }
        f.category = "BILGI".to_string();
        f.label = format!("[BİLGİ] {}", f.label);
        f.explain.push_str(&format!(
            "  >> Bu bulgu karara KATILMADI: dosyanın içeriği {} olarak doğrulandı (mod kimliği + kendi Java paketi). {}",
            t.label, t.note
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn norm_id_basic() {
        assert_eq!(norm_id("CoFH_Core-x.y z"), "cofhcorexyz");
    }

    #[test]
    fn known_good_by_pkg() {
        let names = vec!["cofh/core/Foo".to_string()];
        let t = classify_trusted("cofh_core", &names, "");
        assert!(t.known_good);
        assert_eq!(t.allow_keys, vec!["velocity", "velocity_player", "break_free"]);
        let t2 = classify_trusted("other", &names, "");
        assert!(!t2.known_good);
    }

    fn unimixins_names() -> Vec<String> {
        let mut v: Vec<String> = MIXIN_CORE.iter().map(|s| s.to_string()).collect();
        for i in 0..60 {
            v.push(format!("org/spongepowered/asm/mixin/Gen{}", i));
        }
        v.push("io/github/legacymoddingmc/unimixins/all/AllCore".to_string());
        v.push("com/gtnewhorizon/gtnhmixins/core/GTNHMixinsCore".to_string());
        v.push("makamys/mixingasm/MixinConfigPlugin".to_string());
        v
    }

    #[test]
    fn unimixins_is_infra() {
        let names = unimixins_names();
        let t = classify_trusted("", &names, "org.spongepowered.tools.agent.MixinAgent");
        assert!(t.infra);
        let t = classify_trusted("", &names, "");
        assert!(t.infra);
    }

    #[test]
    fn unimixins_foreign_class_or_agent_rejected() {
        let mut names = unimixins_names();
        names.push("me/cheat/KillAura".to_string());
        assert!(!classify_trusted("", &names, "").infra);
        let names = unimixins_names();
        assert!(!classify_trusted("", &names, "me.cheat.Agent").infra);
        let mut names = unimixins_names();
        names.retain(|n| !n.starts_with(UNIMIXINS_ROOT));
        assert!(!classify_trusted("", &names, "").infra);
    }

    #[test]
    fn bettercombat_and_pehkui_keys() {
        let bc = vec!["net/bettercombat/client/AttackInteractor".to_string()];
        let t = classify_trusted("bettercombat", &bc, "");
        assert!(t.known_good);
        assert!(t.allow_keys.contains(&"attack_through".to_string()));
        assert!(!t.allow_keys.contains(&"killaura".to_string()));
        assert!(!classify_trusted("bettercombatplus", &bc, "").known_good);
        let pk = vec!["virtuoel/pehkui/util/ScaleUtils".to_string()];
        let t = classify_trusted("pehkui", &pk, "");
        assert!(t.known_good);
        assert!(t.allow_keys.contains(&"reach".to_string()));
        assert!(!t.allow_keys.contains(&"esp".to_string()));
        assert!(!classify_trusted("pehkui", &bc, "").known_good);
    }
}
