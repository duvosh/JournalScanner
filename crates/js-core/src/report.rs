use crate::client::*;
use crate::devices::*;
use crate::disk::*;
use crate::events::*;
use crate::jar::*;
use crate::logs::*;
use crate::prefetch::*;
use crate::rx::Rx;
use crate::util::*;
use std::collections::BTreeSet;
use std::sync::OnceLock;

pub const APP_TITLE: &str = concat!("JOURNALSCANNER v", env!("CARGO_PKG_VERSION"));

pub fn goster(anahtar: &str) -> String {
    match anahtar {
        "TEMIZ" => "Temiz".to_string(),
        "SUPHELI" => "Şüpheli".to_string(),
        "YASAKLI" => "Yasaklı".to_string(),
        "YASAKLI_ISLEV" | "YASAKLI ISLEV" => "Yasaklı işlev".to_string(),
        "KESIN" => "Kesin".to_string(),
        "KESIN_HILE" | "KESIN HILE" => "Kesin hile".to_string(),
        "BILGI" => "Bilgi".to_string(),
        "BILGI (kanit yetersiz)" => "Bilgi (kanıt yetersiz)".to_string(),
        "TEMIZ (resmi Fabric modulu)" => "Temiz (resmi Fabric modülü)".to_string(),
        "TEMIZ (sunucu eklentisi)" => "Temiz (sunucu eklentisi)".to_string(),
        _ => match anahtar.strip_prefix("TEMIZ (") {
            Some(rest) => format!("Temiz ({rest}"),
            None => anahtar.to_string(),
        },
    }
}

fn kind_tr(k: &str) -> String {
    match k {
        "call" => "ÇAĞRI",
        "hook" => "MIXIN",
        "write" => "YAZMA",
        "access" => "ERİŞİM",
        "token" => "KİMLİK",
        "ref" => "REFERANS",
        "hint" => "İPUCU",
        "mod" => "MIXIN",
        _ => return k.to_string(),
    }
    .to_string()
}

pub fn cat_tr(c: &str) -> String {
    if c == "KESIN_HILE" {
        return "KESİN HİLE".to_string();
    }
    if c == "YASAKLI_ISLEV" {
        return "YASAKLI İŞLEV".to_string();
    }
    if c == "SUPHELI" {
        return "ŞÜPHELİ".to_string();
    }
    c.to_string()
}

fn ljust(s: &str, w: usize) -> String {
    let n = ulen(s);
    if n >= w {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(w - n))
    }
}

pub fn mod_lines(r: &ScanResult, indent: &str) -> StrList {
    let ind = indent;
    let mut l: StrList = Vec::new();
    let meta = &r.meta;
    l.push(format!("{ind}[{}] {}", goster_buyuk(&r.verdict), r.name));
    let ozet = crate::plain::verdict_summary(r);
    if !ozet.is_empty() {
        l.push(format!("{ind}  Özet     : {}", ozet));
    }
    l.push(format!("{ind}  Yol      : {}", r.file));
    for n in &r.notes {
        if starts(n, "Konum:") {
            l.push(format!("{ind}  Konum    : {}", strip(&n[6..], WS_CHARS)));
        }
    }
    let mut bits: StrList = Vec::new();
    if meta.name.truthy || meta.id.truthy {
        bits.push(format!(
            "{} ({})",
            if meta.name.truthy { &meta.name.s } else { &meta.id.s },
            if meta.id.truthy { meta.id.s.as_str() } else { "?" }
        ));
    }
    if meta.version.truthy {
        bits.push(format!("v{}", meta.version.s));
    }
    if meta.loader.truthy {
        bits.push(meta.loader.s.clone());
    }
    bits.push(format!("{} sınıf", r.class_count));
    l.push(format!("{ind}  Mod      : {}", join(&bits, "  |  ")));
    if r.has_sha && !r.sha256.is_empty() {
        l.push(format!("{ind}  SHA-256  : {}", r.sha256));
    }
    for f in &r.findings {
        l.push(format!("{ind}  >> {}  [{}]", f.label, cat_tr(&f.category)));
        l.push(format!("{ind}     Kısaca     : {}", crate::plain::finding_summary(f)));
        l.push(format!("{ind}     Ne yapıyor : {}", f.explain));
        for u in &f.units {
            let mut head = format!("{ind}     Kod yeri   : {}", u.unit);
            if !u.via.is_empty() {
                head += &format!("   (+ çağırdığı yardımcı sınıflar: {})", join(&u.via, ", "));
            }
            l.push(head);
            let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
            for g in &u.groups {
                for h in g {
                    if !seen.insert((h.cls.clone(), h.detail.clone())) {
                        continue;
                    }
                    let cls = if h.cls != "-" && !h.cls.is_empty() {
                        replace_all(&h.cls, "/", ".")
                    } else {
                        String::new()
                    };
                    let where_ = if !cls.is_empty() && cls != u.unit && !starts(&u.unit, &format!("{cls}.")) {
                        format!("  @ {cls}")
                    } else {
                        String::new()
                    };
                    l.push(format!("{ind}        - [{}] {}{}", kind_tr(&h.kind), h.detail, where_));
                }
            }
        }
        if f.unit_count > f.units.len() as i32 {
            l.push(format!(
                "{ind}     (+{} sınıf daha)",
                f.unit_count - f.units.len() as i32
            ));
        }
    }
    if r.rank > 0 && !r.mixins.is_empty() {
        l.push(format!("{ind}  Mixin listesi:"));
        for m in r.mixins.iter().take(15) {
            l.push(format!(
                "{ind}     {} -> {}",
                m.cls,
                if m.targets.is_empty() {
                    "?".to_string()
                } else {
                    join(&m.targets, ", ")
                }
            ));
            if !m.injections.is_empty() {
                l.push(format!(
                    "{ind}        {}",
                    join(&m.injections[..m.injections.len().min(6)], "; ")
                ));
            }
        }
    }
    for n in &r.notes {
        if !starts(n, "Konum:") {
            l.push(format!("{ind}  Not      : {n}"));
        }
    }
    for a in r.also_at.iter().take(20) {
        let loc = location_note(a);
        l.push(format!(
            "{ind}  Aynı dosya burada da var: {a}{}",
            if loc.is_empty() {
                String::new()
            } else {
                format!("   ({loc})")
            }
        ));
    }
    for s in &r.nested {
        if s.rank > 0 {
            l.push(format!("{ind}  İç içe (jar-in-jar) kütüphane:"));
            l.extend(mod_lines(s, &format!("{ind}     ")));
        }
    }
    l
}

pub fn event_lines(e: &EventResult) -> StrList {
    let mut l: StrList = Vec::new();
    if !e.error.is_empty() {
        l.push(format!("  {}", e.error));
        return l;
    }
    l.push(format!(
        "  Son 5 günde 500/501 olay sayısı: {}   |   System / fsutil.exe işlem birimli: {}",
        e.total_500_501,
        e.findings.len()
    ));
    if e.findings.is_empty() {
        l.push("  System veya fsutil.exe işlem birimli 500/501 olayı YOK.".to_string());
        return l;
    }
    for ev in &e.findings {
        l.push(String::new());
        l.push(format!(
            "  Olay {}  |  {}  |  İşlem birimi: {}  (alan: {})  |  Kayıt #{}",
            ev.event_id, ev.time, ev.process, ev.process_field, ev.record_id
        ));
        for d in ev.data.iter().take(10) {
            l.push(format!("      {} = {}", ljust(&d.0, 22), uslice(&d.1, 160)));
        }
    }
    l
}

pub fn overall_verdict(
    jars: &[ScanResult],
    ev: &EventResult,
    pf: Option<&PrefetchResult>,
    lr: Option<&LogScan>,
) -> String {
    let mut rank = 0;
    for r in jars {
        rank = rank.max(r.rank);
    }
    if let Some(pf) = pf {
        rank = rank.max(prefetch_rank(pf));
    }
    if let Some(lr) = lr {
        rank = rank.max(log_rank(lr));
    }
    if rank >= 3 {
        return "KESIN HILE".to_string();
    }
    if rank == 2 {
        return "YASAKLI ISLEV".to_string();
    }
    if rank == 1 || !ev.findings.is_empty() {
        return "SUPHELI".to_string();
    }
    "TEMIZ".to_string()
}

fn vrank(v: &str) -> i32 {
    match v {
        "KESIN HILE" => 3,
        "YASAKLI ISLEV" => 2,
        "SUPHELI" => 1,
        _ => 0,
    }
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    pub full: String,
    pub summary: String,
    pub verdict: String,
}

pub fn build_report(
    jars: &[ScanResult],
    ev: &EventResult,
    mods_dir: &str,
    pf: Option<&PrefetchResult>,
    lr: Option<&LogScan>,
    dev: Option<&DeviceResult>,
    cl: Option<&ClientResult>,
) -> Report {
    let mut verdict = overall_verdict(jars, ev, pf, lr);
    if let Some(cl) = cl {
        if cl.rank > 0 && vrank(&cl.verdict) > vrank(&verdict) {
            verdict = cl.verdict.clone();
        }
    }
    let mut rep = Report {
        verdict: verdict.clone(),
        ..Default::default()
    };
    let now = fmt_local(now_epoch(), "%Y-%m-%d %H:%M:%S");
    let mut kesin: Vec<&ScanResult> = Vec::new();
    let mut yasak: Vec<&ScanResult> = Vec::new();
    let mut sup: Vec<&ScanResult> = Vec::new();
    let mut temiz: Vec<&ScanResult> = Vec::new();
    let mut fab = 0usize;
    for r in jars {
        if r.rank == 3 {
            kesin.push(r);
        } else if r.rank == 2 {
            yasak.push(r);
        } else if r.rank == 1 {
            sup.push(r);
        } else {
            temiz.push(r);
            if r.official_fabric {
                fab += 1;
            }
        }
    }
    let eq = "=".repeat(78);
    let dash = "-".repeat(78);
    let mut l: StrList = vec![
        eq.clone(),
        format!("{APP_TITLE} - SONUÇ RAPORU"),
        format!("Tarih: {now}"),
        format!("Mods klasörü: {mods_dir}"),
        eq.clone(),
        String::new(),
        format!("GENEL KARAR : {}", goster_buyuk(&verdict)),
        String::new(),
        "[ MOD TARAMASI ]".to_string(),
        format!("  Taranan dosya     : {}", jars.len()),
        format!("  KESİN HİLE        : {}", kesin.len()),
        format!("  YASAKLI İŞLEV     : {}", yasak.len()),
        format!("  ŞÜPHELİ           : {}", sup.len()),
        format!("  TEMİZ             : {}   (resmi Fabric modülü: {})", temiz.len(), fab),
    ];
    for grp in [&kesin, &yasak, &sup] {
        for r in grp.iter() {
            l.push(String::new());
            l.push(dash.clone());
            l.extend(mod_lines(r, ""));
        }
    }
    l.push(String::new());
    l.push(dash.clone());
    l.push("TEMİZ MODLAR:".to_string());
    for r in &temiz {
        l.push(format!(
            "  [OK] {} {}",
            ljust(&r.name, 55),
            if r.official_fabric {
                "(resmi Fabric)".to_string()
            } else if r.meta.id.truthy {
                r.meta.id.s.clone()
            } else {
                String::new()
            }
        ));
    }
    l.push(String::new());
    l.push(eq.clone());
    l.push("[ OLAY GÖRÜNTÜLEYİCİSİ - Ntfs/Operational | 500/501 | System / fsutil.exe ]".to_string());
    l.extend(event_lines(ev));
    l.push(eq.clone());
    if let Some(pf) = pf {
        l.push("[ PREFETCH (.pf) - çalıştırılan programlar ve yükledikleri dosyalar ]".to_string());
        l.extend(prefetch_lines(pf));
        l.push(eq.clone());
    }
    if let Some(lr) = lr {
        l.push(
            "[ LOG TARAMASI - son 5 günün Minecraft logları: hile / yasaklı mod ile açılmış oturumlar ]".to_string(),
        );
        l.extend(log_lines(lr));
        l.push(eq.clone());
    }
    if let Some(cl) = cl {
        l.push(
            "[ AKTİF CLIENT - şu an çalışan Minecraft istemcisi (sürüm, yükleyici, başlatıcı, kullandığı tüm kod) ]"
                .to_string(),
        );
        l.extend(active_lines(cl));
        l.push(eq.clone());
    }
    if let Some(dev) = dev {
        l.push(format!(
            "[ BLUETOOTH / USB - son {} gün (bilgi amaçlıdır, karari etkilemez) ]",
            dev.days
        ));
        l.extend(device_lines(dev));
        l.push(eq.clone());
    }
    rep.full = join(&l, "\n");

    let mut s: StrList = vec![
        format!("GENEL KARAR: {}", goster_buyuk(&verdict)),
        format!(
            "Mod: {} tarandı | KESİN {} | YASAKLI {} | ŞÜPHELİ {} | TEMİZ {}",
            jars.len(),
            kesin.len(),
            yasak.len(),
            sup.len(),
            temiz.len()
        ),
        String::new(),
    ];
    for grp in [&kesin, &yasak, &sup] {
        for r in grp.iter() {
            s.push(format!("[{}] {}", goster_buyuk(&r.verdict), r.name));
            for f in r.findings.iter().take(4) {
                let us: StrList = f.units.iter().take(2).map(|u| u.unit.clone()).collect();
                s.push(format!("  - {}", uslice(&f.label, 70)));
                s.push(format!("    class: {}", uslice(&join(&us, ", "), 120)));
            }
            for n in &r.nested {
                if n.rank > 0 {
                    s.push(format!("  - iç içe: {} [{}]", n.name, goster_buyuk(&n.verdict)));
                }
            }
        }
    }
    rep.summary = join(&s, "\n");
    rep
}

pub fn disk_verdict(d: &DiskResult) -> String {
    let mut rank = 0;
    for r in &d.results {
        rank = rank.max(r.rank);
    }
    if !d.text_hits.is_empty() {
        rank = rank.max(1);
    }
    verdict_by_rank(rank)
}

pub fn text_hit_lines(h: &TextHit, indent: &str) -> StrList {
    vec![
        format!(
            "{indent}[ŞÜPHELİ] {}{}",
            h.file,
            if h.line_no != 0 {
                format!("  (satır {})", h.line_no)
            } else {
                String::new()
            }
        ),
        format!("{indent}  Neden    : {}", h.reason),
        format!("{indent}  İçerik   : {}", h.line),
    ]
}

pub fn disk_lines(d: &DiskResult) -> StrList {
    let st = &d.stats;
    let mut l: StrList = vec![
        format!("  Taranan konumlar : {}", join(&d.roots, ", ")),
        format!(
            "  Dosya: {}  |  Klasör: {}  |  Bellekte açılan arşiv: {}  |  Betik/ayar: {}  |  Erişilemeyen: {}  |  Süre: {:.0} sn",
            st.files, st.dirs, st.archives, st.texts, st.denied, d.duration
        ),
    ];
    if st.containers != 0 || st.loose_groups != 0 {
        l.push(format!(
            "  Açılan kapsayıcı (7z/RAR/tar/gz/xz/bz2/CAB/zst/lz4): {}  |  Jar'a paketlenmemiş sınıf grubu: {}",
            st.containers, st.loose_groups
        ));
    }
    if st.unopened != 0 {
        l.push(format!(
            "  Not: {} arşiv açılamadı (bozuk / desteklenmeyen / parolalı).",
            st.unopened
        ));
    }
    if st.skipped_sys_dirs != 0 {
        l.push(format!(
            "  Not: {} işletim sistemi / üreticisi bilinen program klasörü (Windows, Microsoft/sürücü program klasörleri, mağaza uygulama paketleri, tarayıcı önbellekleri) atlandı. Windows\\Temp, kullanıcı klasörleri, .minecraft ve diğer 3. parti program klasörleri taranır.",
            st.skipped_sys_dirs
        ));
    }
    if st.skipped_loose != 0 {
        l.push(format!(
            "  Not: {} gevşek Java sınıfı (jar'a paketlenmemiş .class) sınır aşıldığı için analize alınamadı.",
            st.skipped_loose
        ));
    }
    if st.skipped_mem != 0 {
        l.push(format!(
            "  UYARI: {} büyük dosya, boş bellek yetersiz olduğu için (programın çökmemesi için) atlandı. Diğer programları (oyun, tarayıcı) kapatıp taramayı yeniden başlatabilirsiniz.",
            st.skipped_mem
        ));
    }
    if st.cloud != 0 {
        l.push(format!(
            "  Not: {} dosya yalnızca bulutta (OneDrive vb.) duruyor, bilgisayarda olmadığı için açılmadı.",
            st.cloud
        ));
    }
    if !d.error.is_empty() {
        l.push(format!("  HATA: {}", d.error));
    }
    if d.stopped {
        l.push("  (Tarama kullanıcı tarafından durduruldu - sonuçlar KISMİ)".to_string());
    }
    if d.results.is_empty() && d.text_hits.is_empty() {
        l.push("  Hile, yasaklı işlevli mod veya şüpheli öğe BULUNAMADI.".to_string());
        return l;
    }
    l.push(format!(
        "  Bulgu: {} dosya, {} başlatıcı/betik kaydı",
        d.results.len(),
        d.text_hits.len()
    ));
    l.push(String::new());
    l.push("BULUNAN DOSYALARIN TAM YOLLARI:".to_string());
    for (n, r) in (1..).zip(d.results.iter()) {
        l.push(format!("  {:>2}. [{}] {}", n, goster_buyuk(&r.verdict), r.file));
        for a in &r.also_at {
            l.push(format!("        kopya: {a}"));
        }
    }
    for h in &d.text_hits {
        l.push(format!("   - [ŞÜPHELİ] {}", h.file));
    }
    for r in &d.results {
        l.push(String::new());
        l.push("-".repeat(78));
        l.extend(mod_lines(r, ""));
    }
    if !d.text_hits.is_empty() {
        l.push(String::new());
        l.push("-".repeat(78));
        l.push("BAŞLATICI / BETİK / AYAR DOSYALARI:".to_string());
        for h in &d.text_hits {
            l.push(String::new());
            l.extend(text_hit_lines(h, "  "));
        }
    }
    l
}

pub fn build_disk_report(d: &DiskResult) -> Report {
    let mut rep = Report {
        verdict: disk_verdict(d),
        ..Default::default()
    };
    let eq = "=".repeat(78);
    let mut l: StrList = vec![
        eq.clone(),
        format!("{APP_TITLE} - DİSK TARAMASI"),
        format!("Tarih: {}", fmt_local(now_epoch(), "%Y-%m-%d %H:%M:%S")),
        eq,
        String::new(),
        format!("DİSK KARARI : {}", goster_buyuk(&rep.verdict)),
        String::new(),
    ];
    l.extend(disk_lines(d));
    rep.full = join(&l, "\n");
    let mut s: StrList = vec![
        format!("DİSK KARARI: {}", goster_buyuk(&rep.verdict)),
        format!(
            "{} dosya tarandı, {} arşiv bellekte açıldı",
            d.stats.files, d.stats.archives
        ),
        String::new(),
    ];
    for r in &d.results {
        s.push(format!("[{}] {}", goster_buyuk(&r.verdict), utail(&r.file, 110)));
        for a in r.also_at.iter().take(3) {
            s.push(format!("  kopya: {}", utail(a, 100)));
        }
        for f in r.findings.iter().take(3) {
            s.push(format!("  - {}", uslice(&f.label, 80)));
        }
        for sub in &r.nested {
            if sub.rank > 0 {
                s.push(format!("  - iç arşiv: {} [{}]", sub.name, goster_buyuk(&sub.verdict)));
            }
        }
    }
    rep.summary = join(&s, "\n");
    rep
}

fn log_place(d: &str) -> String {
    let low = py_lower(&replace_all(d, "\\", "/"));
    if has(&low, "/.tlauncher/") {
        return "TLauncher oyun log klasörü".to_string();
    }
    if has(&low, "/curseforge/") {
        return "CurseForge instance log klasörü".to_string();
    }
    if has(&low, "prismlauncher") || has(&low, "multimc") {
        return "Prism/MultiMC instance log klasörü".to_string();
    }
    if has(&low, "modrinth") {
        return "Modrinth instance log klasörü".to_string();
    }
    if has(&low, "/.minecraft/logs") {
        return ".minecraft log klasörü".to_string();
    }
    "Minecraft log klasörü".to_string()
}

pub fn log_result_lines(r: &LogResult, indent: &str) -> StrList {
    static DATE: OnceLock<Rx> = OnceLock::new();
    let date = DATE.get_or_init(|| Rx::new(r"\d{4}-\d{2}-\d{2}", 0));
    let ind = indent;
    let info = &r.info;
    let mut l: StrList = vec![
        format!("{ind}[{}] {}", goster_buyuk(&r.verdict), r.name),
        format!("{ind}  Log dosyası : {}", r.file),
        format!("{ind}  Konum       : {}", log_place(&r.dir)),
        format!(
            "{ind}  Tarih       : {}",
            fmt_local(
                r.mtime,
                if date.search(r.name.as_bytes(), 0).is_some() {
                    "%Y-%m-%d"
                } else {
                    "%Y-%m-%d %H:%M"
                }
            )
        ),
    ];
    if let Some(u) = &info.user {
        l.push(format!("{ind}  Oyuncu      : {u}"));
    }
    let mut game: StrList = Vec::new();
    if let Some(mc) = &info.mc {
        game.push(format!("Minecraft {mc}"));
    }
    if let Some(ld) = &info.loader {
        game.push(ld.clone());
    }
    game.push(format!("{} mod yüklendi", r.mods_total));
    l.push(format!("{ind}  Oyun        : {}", join(&game, "  |  ")));
    if !info.servers.is_empty() {
        l.push(format!(
            "{ind}  Oyuna giriş : SUNUCUYA BAĞLANDI -> {}",
            join(&info.servers, ", ")
        ));
    } else if info.singleplayer {
        l.push(format!("{ind}  Oyuna giriş : Tek oyunculu dünyaya girdi"));
    } else {
        l.push(format!(
            "{ind}  Oyuna giriş : Oyun bu modlarla AÇILDI (bu logda sunucu/dünya girişi kaydı yok)"
        ));
    }
    for o in &r.same_session {
        l.push(format!("{ind}  Aynı oturumun diğer kaydı: {o}"));
    }
    for h in &r.hits {
        let m = &h.r#mod;
        let title = match h.known {
            Some(k) => k.desc.to_string(),
            None => format!("{} {}", m.id, m.version),
        };
        l.push(format!("{ind}  >> {title}  [{}]", cat_tr(&h.category)));
        l.push(format!(
            "{ind}     Log satırı : {}   \"{}\"   ({})",
            m.line,
            uslice(&m.raw, 120),
            m.source
        ));
        l.push(format!(
            "{ind}     Mod kimliği: {}   sürüm: {}{}",
            m.id,
            m.version,
            if m.nested {
                "   (başka bir modun içine gömülü)"
            } else {
                ""
            }
        ));
        if !h.jar.is_empty() {
            l.push(format!(
                "{ind}     Jar        : {}   ({})",
                h.jar,
                if h.same {
                    "kimlik + sürüm AYNI"
                } else {
                    "aynı kimlik, FARKLI sürüm - yüklenen jar değil"
                }
            ));
        } else {
            l.push(format!(
                "{ind}     Jar        : diskte bulunamadı (silinmiş / taşınmış / başka klasörde olabilir)"
            ));
        }
        if h.basis == "kod" && h.code.is_some() {
            if let Some(code) = &h.code {
                l.push(format!(
                    "{ind}     Karar      : Jar'in KODU okundu -> {}{}",
                    code.verdict,
                    if h.known.is_some() {
                        String::new()
                    } else {
                        format!(
                            "   (kimliği yasaklı listede YOK; mod kendini '{}' diye tanıtıyor ama kodu hile)",
                            m.id
                        )
                    }
                ));
                for f in code.findings.iter().take(5) {
                    let us: StrList = f.units.iter().take(2).map(|u| u.unit.clone()).collect();
                    l.push(format!(
                        "{ind}        - {}  [{}]{}",
                        f.label,
                        cat_tr(&f.category),
                        if us.is_empty() {
                            String::new()
                        } else {
                            format!("   @ {}", join(&us, ", "))
                        }
                    ));
                }
            }
        } else if let Some(k) = h.known {
            l.push(format!(
                "{ind}     Karar      : Oyunun KENDİ yükleme kaydındaki mod KİMLİĞİ '{}' -> {}",
                m.id, k.desc
            ));
            l.push(format!(
                "{ind}                  (kimlik doğrulaması: {}; dosya adına BAKILMAZ)",
                k.source
            ));
            if let Some(code) = &h.code {
                if !h.same {
                    l.push(format!(
                        "{ind}                  Diskteki farklı sürüm jar'in kod sonucu: {}",
                        code.verdict
                    ));
                }
            }
        }
    }
    l
}

pub fn log_lines(lr: &LogScan) -> StrList {
    let mut l: StrList = vec!["  Taranan log klasörleri:".to_string()];
    for d in &lr.dirs {
        l.push(format!("    - {d}"));
    }
    if lr.dirs.is_empty() {
        l.push("    (Minecraft log klasörü bulunamadı)".to_string());
    }
    l.push(format!(
        "  Son {} günde okunan log dosyası: {}   |   Kodu okunan mod jar'i: {}   |   Süre: {:.1} sn",
        lr.days,
        lr.files.len(),
        lr.jars_checked,
        lr.duration
    ));
    for e in lr.errors.iter().take(10) {
        l.push(format!("  Not: {e}"));
    }
    if lr.results.is_empty() {
        l.push(format!(
            "  Son {} günlük loglarda hile client'i / yasaklı mod ile açılmış oyun oturumu BULUNAMADI.",
            lr.days
        ));
    } else {
        l.push(format!("  Bulgu: {} oturum", lr.results.len()));
        l.push(String::new());
        l.push("BULUNAN LOGLARIN TAM YOLLARI:".to_string());
        for (n, r) in (1..).zip(lr.results.iter()) {
            l.push(format!("  {:>2}. [{}] {}", n, goster_buyuk(&r.verdict), r.file));
        }
        for r in &lr.results {
            l.push(String::new());
            l.push("-".repeat(78));
            l.extend(log_result_lines(r, ""));
        }
    }
    if !lr.files.is_empty() {
        l.push(String::new());
        l.push(format!("OKUNAN TÜM LOGLAR (son {} gün):", lr.days));
        let mut fs = lr.files.clone();
        fs.sort_by(|a, b| b.mtime.partial_cmp(&a.mtime).unwrap_or(std::cmp::Ordering::Equal));
        for f in &fs {
            l.push(format!(
                "  {}  |  {:>4} mod  |  {}",
                fmt_local(f.mtime, "%Y-%m-%d %H:%M"),
                f.mods,
                f.file
            ));
        }
    }
    l
}

pub fn prefetch_finding_lines(f: &PfFinding, indent: &str) -> StrList {
    let ind = indent;
    let mut l: StrList = vec![
        format!("{ind}[{}] {}", cat_tr(&f.category), f.label),
        format!(
            "{ind}  Program        : {}   (prefetch kaydı: {}, sürüm {})",
            f.exe, f.pf, f.version
        ),
        format!("{ind}  Çalışma sayısı : {}", f.run_count),
        format!(
            "{ind}  Son çalışmalar : {}",
            if f.run_times.is_empty() {
                "-".to_string()
            } else {
                join(&f.run_times, ", ")
            }
        ),
    ];
    for x in &f.files {
        l.push(format!("{ind}  Dosya          : {x}"));
    }
    l.push(format!("{ind}  Açıklama       : {}", f.explain));
    if let Some(sr) = &f.scan_result {
        l.push(format!("{ind}  Dosyanın kod analizi:"));
        l.extend(mod_lines(sr, &format!("{ind}     ")));
    }
    l
}

pub fn prefetch_lines(pr: &PrefetchResult) -> StrList {
    let mut l: StrList = Vec::new();
    let mut durum = "bilinmiyor";
    if let Some(e) = pr.enabled {
        durum = match e {
            0 => "KAPALI",
            1 => "yalnızca uygulama başlatma",
            2 => "yalnızca açılış",
            3 => "AÇIK",
            _ => "bilinmiyor",
        };
    }
    l.push(format!(
        "  Prefetch durumu: {durum}  |  .pf dosyası: {}  |  ayrıştırılan: {}  |  okunamayan: {}  |  Java süreci kaydı: {}  |  içeriği incelenen dosya: {}",
        pr.pf_count, pr.parsed, pr.failed, pr.java_pf, pr.checked_files
    ));
    if !pr.error.is_empty() {
        l.push(format!("  {}", pr.error));
    }
    if pr.self_skipped != 0 {
        l.push(format!(
            "  Not: tarayıcının kendi çalışma kaydı ({} adet) dışarıda bırakıldı - tarama sırasında açtığımız dosyalar kanıt değildir.",
            pr.self_skipped
        ));
    }
    if pr.findings.is_empty() {
        if pr.error.is_empty() {
            l.push("  Hile / yasaklı işlev ile ilgili prefetch kaydı BULUNAMADI.".to_string());
        }
        return l;
    }
    for f in &pr.findings {
        l.push(String::new());
        l.extend(prefetch_finding_lines(f, "  "));
    }
    l
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn goster_anahtarlar() {
        assert_eq!(goster("TEMIZ"), "Temiz");
        assert_eq!(goster("SUPHELI"), "Şüpheli");
        assert_eq!(goster("YASAKLI_ISLEV"), "Yasaklı işlev");
        assert_eq!(goster("YASAKLI ISLEV"), "Yasaklı işlev");
        assert_eq!(goster("KESIN_HILE"), "Kesin hile");
        assert_eq!(goster("KESIN HILE"), "Kesin hile");
        assert_eq!(goster("BILGI"), "Bilgi");
        assert_eq!(goster("TEMIZ (resmi Fabric modulu)"), "Temiz (resmi Fabric modülü)");
        assert_eq!(goster("TEMIZ (Mixin kutuphanesi)"), "Temiz (Mixin kutuphanesi)");
    }

    #[test]
    fn goster_bilinmeyen_aynen() {
        assert_eq!(goster("???"), "???");
        assert_eq!(goster(""), "");
    }

    #[test]
    fn cat_tr_eslemesi() {
        assert_eq!(cat_tr("KESIN_HILE"), "KESİN HİLE");
        assert_eq!(cat_tr("YASAKLI_ISLEV"), "YASAKLI İŞLEV");
        assert_eq!(cat_tr("SUPHELI"), "ŞÜPHELİ");
        assert_eq!(cat_tr("X"), "X");
    }

    #[test]
    fn goster_buyuk_eslemesi() {
        assert_eq!(goster_buyuk("KESIN HILE"), "KESİN HİLE");
        assert_eq!(goster_buyuk("YASAKLI ISLEV"), "YASAKLI İŞLEV");
        assert_eq!(goster_buyuk("SUPHELI"), "ŞÜPHELİ");
        assert_eq!(
            goster_buyuk("TEMIZ (resmi Fabric modulu)"),
            "TEMİZ (resmi Fabric modülü)"
        );
        assert_eq!(goster_buyuk("BILGI (kanit yetersiz)"), "BİLGİ (kanıt yetersiz)");
        assert_eq!(goster_buyuk("evil.jar"), "evil.jar");
    }

    #[test]
    fn ljust_ve_vrank() {
        assert_eq!(vrank("KESIN HILE"), 3);
        assert_eq!(vrank("TEMIZ"), 0);
    }
}
