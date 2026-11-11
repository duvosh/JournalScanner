//! Bulgular ve kararlar için herkesin anlayacağı kısa özetler ("Kısaca" / "Özet" satırları).
//! Teknik açıklamanın YERİNE geçmez; raporda teknik ayrıntı aynen altında durur.

use crate::data::SIGNATURES;
use crate::jar::{Finding, ScanResult};

fn signature_label(key: &str) -> Option<&'static str> {
    SIGNATURES.iter().find(|s| s.key == key).map(|s| s.label)
}

/// Motorun kendi (imza dışı) bulguları için sade açıklama.
fn engine_summary(key: &str, category: &str) -> Option<&'static str> {
    let certain = category == "KESIN_HILE";
    Some(match key {
        "known_client" => "Bilinen bir hile programının kodu bu dosyanın içinde.",
        "client_addon" => "Bir hile programına eklenti olarak yazılmış; o hile programıyla birlikte çalışan ek hile özellikleri.",
        "cheat_source" => "Bir hile programının kaynak kodu (derlenmeye hazır hali) bu arşivde.",
        "client_layout" if certain => {
            "Hile programlarına özgü menü/modül yapısı var (Savaş, Hareket gibi kategoriler ve oyuncu adına vuran/nişan alan kod)."
        }
        "client_layout" => "Hile programlarına benzeyen bir menü/modül yapısı var ama oyuna dokunduğu doğrulanamadı.",
        "cheat_terms" if certain => {
            "Oyunu etkileyen kodun içinde hile özelliklerinin adları geçiyor (ör. KillAura, TriggerBot) ve dosyada bunu destekleyen başka kanıt da var."
        }
        "cheat_terms" => {
            "Kodda bir hile özelliğinin adı geçiyor; ama bu tek başına kanıt değil (ör. bir sohbet filtresi de aynı kelimeyi içerebilir)."
        }
        "memory_loader" | "hidden_loader" | "packed_loader" => {
            "Mod asıl kodunu saklıyor ve oyun sırasında gizlice çalıştırıyor; bu yöntem gizli hile ve hesap çalıcı yükleyicilerinde kullanılır."
        }
        "native_module_client" => {
            "Hile özelliklerine benzeyen modüllerin kodu, okunmasın diye yerel koda (DLL) gömülerek gizlenmiş."
        }
        "handle_closer" | "handle_closer_mod" if certain => {
            "Oyun açıkken hile dosyasının silinebilmesini sağlayan bir iz silme aracı içeriyor."
        }
        "handle_closer" | "handle_closer_mod" => {
            "Başka programların açık dosyalarını kapatabilen bir araç içeriyor; oyunla bağlantısı doğrulanamadı."
        }
        "injector" => "Çalışan Minecraft'a dışarıdan kod sokan bir yükleyici (enjektör).",
        "native_injector" => "İçinde, Minecraft'a dışarıdan kod sokan bir Windows programı var.",
        "java_agent" if certain => "Minecraft'ın kodunu oyun sırasında değiştiren, kendini gizleyen bir Java ajanı.",
        "java_agent" => {
            "Minecraft'ın kodunu değiştirebilen bir Java ajanı. Başlatıcılar ve mod yükleyicileri de bunu kullanır; tek başına kanıt değil."
        }
        "keyword_game_client" => "Dosyada oyun istemcisine ve hile kelimelerine benzeyen izler var; tek başına kanıt değil.",
        "obfuscated" => "Kodun adları okunmasın diye karıştırılmış (karartılmış); tek başına kanıt değil.",
        "encrypted_java" => "Şifrelenmiş Java kodu taşıyor; tek başına kanıt değil.",
        "hidden_classes" => "Bazı kod dosyaları farklı bir uzantıyla saklanmış; tek başına kanıt değil.",
        "fake_fabric" => "Fabric moduna benzemeye çalışan ama yapısı tutmayan bir arşiv; tek başına kanıt değil.",
        "renamed_jar" | "disguised_file" => "Mod dosyasının uzantısı değiştirilmiş; tek başına kanıt değil.",
        _ => return None,
    })
}

/// Bir bulgunun herkesin anlayacağı tek cümlelik özeti.
pub fn finding_summary(f: &Finding) -> String {
    if f.category == "BILGI" {
        return "Bilgi amaçlı; karara katılmadı (dosyanın ne olduğu içerikten doğrulandı).".to_string();
    }
    if let Some(s) = engine_summary(&f.key, &f.category) {
        return s.to_string();
    }
    let name = signature_label(&f.key).unwrap_or(f.label.as_str());
    match f.category.as_str() {
        "KESIN_HILE" => format!(
            "Kod, '{}' hilesinin yaptığı işi yapıyor ve dosyada bunu destekleyen ikinci bir kanıt da var.",
            name
        ),
        "YASAKLI_ISLEV" => format!("Sunucuda yasak olan bir işlev var: {}.", name),
        "SUPHELI" => format!(
            "Kod, '{}' hilesine benzer bir şey yapıyor; ama meşru modlar da bunu yapabildiği ve dosyada ikinci bir kanıt olmadığı için kesin sayılmadı. Elle kontrol edin.",
            name
        ),
        _ => f.label.clone(),
    }
}

fn labels(r: &ScanResult, cat: &str, max: usize) -> String {
    let mut v: Vec<String> = Vec::new();
    for f in &r.findings {
        if f.category == cat && !v.contains(&f.label) {
            v.push(f.label.clone());
        }
    }
    let more = v.len().saturating_sub(max);
    v.truncate(max);
    let mut s = v.join(", ");
    if more > 0 {
        s.push_str(&format!(" (+{} bulgu daha)", more));
    }
    s
}

fn nested_with_rank(r: &ScanResult, rank: i32) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for n in &r.nested {
        if n.rank == rank {
            out.push(n.name.clone());
        }
    }
    out
}

/// Dosyanın kararını tek cümlede açıklar. Temiz ve bilgi bulgusu olmayan dosyalar için boş döner.
pub fn verdict_summary(r: &ScanResult) -> String {
    let own = |cat: &str| r.findings.iter().any(|f| f.category == cat);
    let nested_note = |rank: i32| -> String {
        let n = nested_with_rank(r, rank);
        if n.is_empty() {
            String::new()
        } else {
            format!(" İçine gömülü dosyada da bulundu: {}.", n.join(", "))
        }
    };
    match r.rank {
        3 => {
            if own("KESIN_HILE") {
                format!(
                    "Kesin hile: {}. Bu karar ancak dosyanın hile olduğu kanıtlandığında verilir.{}",
                    labels(r, "KESIN_HILE", 3),
                    nested_note(3)
                )
            } else {
                format!(
                    "Kesin hile, içine gömülü dosyada: {}.",
                    nested_with_rank(r, 3).join(", ")
                )
            }
        }
        2 => {
            if own("YASAKLI_ISLEV") {
                format!(
                    "Hile programı değil ama sunucuda yasak olan bir işlev var: {}.{}",
                    labels(r, "YASAKLI_ISLEV", 3),
                    nested_note(2)
                )
            } else {
                format!(
                    "İçine gömülü dosyada yasak bir işlev var: {}.",
                    nested_with_rank(r, 2).join(", ")
                )
            }
        }
        1 => {
            if own("SUPHELI") {
                format!(
                    "Kesin kanıt yok; hileye benzeyen şeyler var: {}. Yetkili elle kontrol etmeli.{}",
                    labels(r, "SUPHELI", 3),
                    nested_note(1)
                )
            } else {
                format!(
                    "İçine gömülü dosyada şüpheli şeyler var: {}. Yetkili elle kontrol etmeli.",
                    nested_with_rank(r, 1).join(", ")
                )
            }
        }
        _ => {
            if r.findings.iter().any(|f| f.category == "BILGI") {
                "Temiz: bazı bulgular var ama dosyanın ne olduğu içerikten doğrulandı, karara katılmadı.".to_string()
            } else {
                String::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(key: &str, label: &str, cat: &str) -> Finding {
        let mut x = Finding::default();
        x.key = key.to_string();
        x.label = label.to_string();
        x.category = cat.to_string();
        x
    }

    #[test]
    fn summaries_by_category() {
        assert!(finding_summary(&f("reach", "Reach", "SUPHELI")).contains("kesin sayılmadı"));
        assert!(finding_summary(&f("reach", "Reach", "KESIN_HILE")).contains("ikinci bir kanıt"));
        assert!(finding_summary(&f("known_client", "Wurst", "KESIN_HILE")).contains("hile programının"));
        assert!(finding_summary(&f("reach", "Reach", "BILGI")).starts_with("Bilgi"));
        assert!(finding_summary(&f("java_agent", "x", "SUPHELI")).contains("tek başına kanıt değil"));
    }

    #[test]
    fn verdict_lines() {
        let mut r = ScanResult::default();
        assert_eq!(verdict_summary(&r), "");
        r.rank = 1;
        r.findings.push(f("reach", "Reach", "SUPHELI"));
        assert!(verdict_summary(&r).starts_with("Kesin kanıt yok"));
        r.rank = 3;
        r.findings.push(f("known_client", "Wurst", "KESIN_HILE"));
        assert!(verdict_summary(&r).contains("Wurst"));
        let mut outer = ScanResult::default();
        outer.rank = 3;
        let mut inner = ScanResult::default();
        inner.rank = 3;
        inner.name = "ic.jar".to_string();
        outer.nested.push(inner);
        assert!(verdict_summary(&outer).contains("ic.jar"));
    }
}
