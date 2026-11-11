#![allow(clippy::field_reassign_with_default)]

use crate::classfile::*;
use crate::data::*;
use crate::json::{jget, jstr, read_json_bytes, JPtr, JVal};
use crate::rx::Rx;
use crate::util::*;
use crate::zipr::*;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub use crate::selfid::{is_own_component, own_tool_markers};
pub use crate::trusted::{apply_known_good, classify_trusted};

#[derive(Debug, Clone, Default)]
pub struct Row {
    pub kind: String,
    pub detail: String,
    pub cls: String,
    pub concept: String,
}
pub type RowGroup = Vec<Row>;

#[derive(Debug, Clone, Default)]
pub struct Unit {
    pub unit: String,
    pub merged: bool,
    pub via: StrList,
    pub groups: Vec<RowGroup>,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub key: String,
    pub label: String,
    pub category: String,
    pub explain: String,
    pub units: Vec<Unit>,
    pub unit_count: i32,
}
impl Default for Finding {
    fn default() -> Self {
        Finding {
            key: String::new(),
            label: String::new(),
            category: String::new(),
            explain: String::new(),
            units: Vec::new(),
            unit_count: -1,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MVal {
    pub present: bool,
    pub truthy: bool,
    pub s: String,
}
impl MVal {
    pub fn set_str(&mut self, v: &str) {
        self.present = true;
        self.truthy = !v.is_empty();
        self.s = v.to_string();
    }
    pub fn set_json(&mut self, v: Option<&JVal>) {
        self.present = v.is_some();
        self.truthy = v.is_some_and(|v| v.truthy());
        self.s = v.map_or(String::new(), |v| v.py_str());
        if let Some(v) = v {
            if v.t == crate::json::JType::Nul {
                self.s.clear();
            }
        }
    }
    pub fn clear(&mut self) {
        self.present = false;
        self.truthy = false;
        self.s.clear();
    }
}

#[derive(Debug, Clone, Default)]
pub struct ModMeta {
    pub loader: MVal,
    pub id: MVal,
    pub name: MVal,
    pub version: MVal,
    pub description: MVal,
    pub environment: MVal,
    pub authors: StrList,
    pub mixin_configs: StrList,
}

#[derive(Debug, Clone, Default)]
pub struct MixinInfo {
    pub cls: String,
    pub targets: StrList,
    pub injections: StrList,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub file: String,
    pub name: String,
    pub sha256: String,
    pub has_sha: bool,
    pub size: u64,
    pub verdict: String,
    pub rank: i32,
    pub meta: ModMeta,
    pub official_fabric: bool,
    pub trusted_infra: bool,
    pub server_plugin: bool,
    pub pkg_summary: StrList,
    pub trust_label: String,
    pub class_count: i32,
    pub mixins: Vec<MixinInfo>,
    pub findings: Vec<Finding>,
    pub notes: StrList,
    pub nested: Vec<ScanResult>,
    pub error: String,
    pub kind: String,
    pub relevant: bool,
    pub text_encoded: String,
    pub also_at: StrList,
}
impl Default for ScanResult {
    fn default() -> Self {
        ScanResult {
            file: String::new(),
            name: String::new(),
            sha256: String::new(),
            has_sha: true,
            size: 0,
            verdict: "TEMIZ".to_string(),
            rank: 0,
            meta: ModMeta::default(),
            official_fabric: false,
            trusted_infra: false,
            server_plugin: false,
            pkg_summary: Vec::new(),
            trust_label: String::new(),
            class_count: 0,
            mixins: Vec::new(),
            findings: Vec::new(),
            notes: Vec::new(),
            nested: Vec::new(),
            error: String::new(),
            kind: String::new(),
            relevant: true,
            text_encoded: String::new(),
            also_at: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TrustInfo {
    pub infra: bool,
    pub known_good: bool,
    pub label: String,
    pub note: String,
    pub allow_keys: StrList,
}

const MAX_INNER: u64 = 150 * 1024 * 1024;
const MAX_NESTED_DEPTH: i32 = 3;
const SMALL_MOD_UNITS: usize = 40;
const MAX_CHAIN: usize = 40;

pub fn shannon_entropy(b: &[u8]) -> f64 {
    if b.is_empty() {
        return 0.0;
    }
    let mut cnt = [0usize; 256];
    for &c in b {
        cnt[c as usize] += 1;
    }
    let n = b.len() as f64;
    let mut h = 0.0f64;
    for &c in cnt.iter() {
        if c != 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

#[derive(Default)]
struct DerStat {
    nodes: i32,
    oids: i32,
}

fn der_walk(d: &[u8], depth: i32, st: &mut DerStat, mut used: Option<&mut usize>) -> bool {
    if depth > 24 {
        return false;
    }
    let n = d.len();
    let mut pos = 0usize;
    while pos < n {
        if used.is_some() && pos + 1 < n && d[pos] == 0 && d[pos + 1] == 0 {
            if let Some(u) = used.as_deref_mut() {
                *u = pos + 2;
            }
            return true;
        }
        let tag = d[pos];
        if (tag & 0x1f) == 0x1f || pos + 2 > n {
            return false; // çok baytlı etiket gerçek imzalarda yok
        }
        let mut hdr = 2usize;
        let mut len = 0usize;
        let l0 = d[pos + 1];
        let mut indef = false;
        if l0 < 0x80 {
            len = l0 as usize;
        } else if l0 == 0x80 {
            if tag & 0x20 == 0 {
                return false;
            }
            indef = true;
        } else {
            let nb = (l0 & 0x7f) as usize;
            if nb > 4 || pos + 2 + nb > n {
                return false;
            }
            for i in 0..nb {
                len = (len << 8) | d[pos + 2 + i] as usize;
            }
            hdr = 2 + nb;
        }
        st.nodes += 1;
        if st.nodes > 200000 {
            return false;
        }
        if tag == 0x06 {
            st.oids += 1;
        }
        let cstart = pos + hdr;
        if indef {
            let mut u = 0usize;
            let c = match d.get(cstart..) {
                Some(c) => c,
                None => return false,
            };
            if !der_walk(c, depth + 1, st, Some(&mut u)) {
                return false;
            }
            pos += hdr + u;
            continue;
        }
        if pos + hdr + len > n {
            return false;
        }
        let c = &d[cstart..cstart + len];
        if tag & 0x20 != 0 {
            if !der_walk(c, depth + 1, st, None) {
                return false;
            }
        } else if tag == 0x04 && len >= 4 && c[0] == 0x30 {
            let mut s2 = DerStat::default();
            if der_walk(c, depth + 1, &mut s2, None) {
                st.nodes += s2.nodes;
                st.oids += s2.oids;
            }
        }
        pos += hdr + len;
    }
    used.is_none() // belirsiz uzunluklu yapı EOC olmadan bitemez
}

pub fn is_der_crypto_blob(d: &[u8]) -> bool {
    let n = d.len();
    if n >= 24 && (d[..4] == [0xFE, 0xED, 0xFE, 0xED] || d[..4] == [0xCE, 0xCE, 0xCE, 0xCE]) {
        let ver = u32::from_be_bytes([d[4], d[5], d[6], d[7]]);
        let cnt = u32::from_be_bytes([d[8], d[9], d[10], d[11]]);
        let tag = u32::from_be_bytes([d[12], d[13], d[14], d[15]]);
        let alen = ((d[16] as usize) << 8) | d[17] as usize;
        if (ver == 1 || ver == 2)
            && (1..100000).contains(&cnt)
            && (1..=3).contains(&tag)
            && (1..256).contains(&alen)
            && 18 + alen <= n
        {
            let printable = d[18..18 + alen].iter().all(|&c| (0x20..=0x7e).contains(&c));
            if printable {
                return true;
            }
        }
        return false;
    }
    if n < 16 || d[0] != 0x30 {
        return false;
    }
    {
        let mut st = DerStat::default();
        if !der_walk(d, 0, &mut st, None) || st.oids < 4 {
            return false;
        }
    }
    let p: usize;
    let mut len = 0usize;
    let mut indefinite = false;
    if d[1] < 0x80 {
        len = d[1] as usize;
        p = 2;
    } else if d[1] == 0x80 {
        indefinite = true;
        p = 2;
    } else {
        let nb = (d[1] & 0x7f) as usize;
        if !(1..=4).contains(&nb) || 2 + nb >= n {
            return false;
        }
        for i in 0..nb {
            len = (len << 8) | d[2 + i] as usize;
        }
        p = 2 + nb;
    }
    if indefinite {
        if d[n - 1] != 0 || d[n - 2] != 0 {
            return false;
        }
    } else if p + len != n {
        return false;
    }
    if n - p < 12 {
        return false;
    }
    let q = &d[p..];
    if q[0] == 0x02 && q[1] == 0x01 && q[2] == 0x03 {
        return true; // PKCS#12 PFX v3
    }
    const P7: [u8; 10] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07];
    if q[..P7.len()] == P7 {
        return true; // PKCS#7 / CMS (jar imzası)
    }
    if q[0] == 0x30 && (q[1] & 0x80) != 0 {
        let h = 2 + (q[1] & 0x7f) as usize;
        if h + 5 <= n - p
            && q[h] == 0xA0
            && q[h + 1] == 0x03
            && q[h + 2] == 0x02
            && q[h + 3] == 0x01
            && q[h + 4] <= 0x02
        {
            return true;
        }
    }
    false
}

pub fn category_rank(cat: &str) -> i32 {
    match cat {
        "KESIN_HILE" => 3,
        "YASAKLI_ISLEV" => 2,
        "SUPHELI" => 1,
        _ => 0,
    }
}
pub fn verdict_by_rank(rank: i32) -> String {
    match rank {
        3 => "KESIN HILE",
        2 => "YASAKLI ISLEV",
        1 => "SUPHELI",
        _ => "TEMIZ",
    }
    .to_string()
}

pub fn bcontains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > hay.len() {
        return false;
    }
    memchr::memmem::find(hay, needle).is_some()
}

fn bstarts(b: &[u8], p: &[u8]) -> bool {
    b.starts_with(p)
}

#[derive(Default)]
struct MI {
    inter: HashSet<&'static str>,
    names: HashSet<&'static str>,
    owners: HashSet<&'static str>,
}

struct Names {
    classes: HashMap<&'static str, HashSet<&'static str>>,
    members: HashMap<&'static str, MI>,
    readable: HashMap<&'static str, &'static str>,
    client_only_classes: HashSet<&'static str>,
    known_pfx: Vec<&'static str>,
    known_api_bytes: Vec<&'static str>,
    empty: HashSet<&'static str>,
    players: HashSet<&'static str>,
    rot: HashSet<&'static str>,
    kb_input: HashSet<&'static str>,
}

impl Names {
    fn new() -> Names {
        let mut classes: HashMap<&'static str, HashSet<&'static str>> = HashMap::new();
        for kv in MC_CLASSES.iter() {
            classes.insert(kv.0, kv.1.iter().copied().collect());
        }
        let mut og: HashMap<&'static str, &'static [&'static str]> = HashMap::new();
        for kv in MC_OWNER_GROUPS.iter() {
            og.insert(kv.0, kv.1);
        }
        let mut members: HashMap<&'static str, MI> = HashMap::new();
        for m in MC_MEMBERS.iter() {
            let mut x = MI::default();
            x.inter.extend(m.inter.iter().copied());
            x.names.extend(m.names.iter().copied());
            for g in m.owner.split('+') {
                let Some(list) = og.get(g) else { continue };
                for ck in list.iter() {
                    if let Some(c) = classes.get(ck) {
                        x.owners.extend(c.iter().copied());
                    }
                }
            }
            members.insert(m.key, x);
        }
        let mut readable = HashMap::new();
        for kv in MC_READABLE.iter() {
            readable.insert(kv.0, kv.1);
        }
        let mut client_only_classes = HashSet::new();
        for kv in MC_CLASSES.iter() {
            let cl = kv.1.iter().any(|y| y.starts_with("net/minecraft/client/"));
            if !cl {
                continue;
            }
            for x in kv.1.iter() {
                if x.contains("/class_") {
                    client_only_classes.insert(*x);
                }
            }
        }
        let known_pfx: Vec<&'static str> = KNOWN_CLIENTS.iter().map(|kv| kv.0).collect();
        let mut api: BTreeSet<&'static str> = BTreeSet::new();
        for kv in KNOWN_CLIENT_APIS.iter() {
            api.insert(kv.0);
        }
        for kv in KNOWN_CLIENTS.iter().take(22) {
            api.insert(kv.0);
        }
        let known_api_bytes: Vec<&'static str> = api.into_iter().collect();
        let mut n = Names {
            classes,
            members,
            readable,
            client_only_classes,
            known_pfx,
            known_api_bytes,
            empty: HashSet::new(),
            players: HashSet::new(),
            rot: HashSet::new(),
            kb_input: HashSet::new(),
        };
        for k in ["C_CLIENT_PLAYER", "C_ABSTRACT_CLIENT_PLAYER", "C_PLAYER"] {
            let s: Vec<&'static str> = n.cls(k).iter().copied().collect();
            n.players.extend(s);
        }
        for k in ["M_SET_YAW", "M_SET_PITCH", "M_CHANGE_LOOK"] {
            let Some(m) = n.members.get(k) else { continue };
            let mut v: Vec<&'static str> = m.inter.iter().copied().collect();
            v.extend(m.names.iter().copied());
            n.rot.extend(v);
        }
        for k in ["C_INPUT", "C_KEYBOARD_INPUT"] {
            let s: Vec<&'static str> = n.cls(k).iter().copied().collect();
            n.kb_input.extend(s);
        }
        n
    }
    fn cls(&self, k: &str) -> &HashSet<&'static str> {
        self.classes.get(k).unwrap_or(&self.empty)
    }
    fn mem(&self, k: &str) -> Option<&MI> {
        self.members.get(k)
    }
}

fn nm() -> &'static Names {
    static N: OnceLock<Names> = OnceLock::new();
    N.get_or_init(Names::new)
}

fn readable_tok(t: &str) -> String {
    match nm().readable.get(t) {
        Some(r) => r.to_string(),
        None => t.to_string(),
    }
}
fn short_cls(c: &str) -> String {
    if c.is_empty() {
        return "?".to_string();
    }
    if let Some(r) = nm().readable.get(c) {
        if !r.is_empty() {
            return r.to_string();
        }
    }
    rpartition_tail(c, "/")
}
fn dotted(c: &str) -> String {
    if c.is_empty() {
        "?".to_string()
    } else {
        replace_all(c, "/", ".")
    }
}
fn last_seg(s: &str, sep: &str) -> String {
    rpartition_tail(s, sep)
}
fn first_seg<'a>(s: &'a str, sep: &str) -> &'a str {
    match s.find(sep) {
        Some(k) => &s[..k],
        None => s,
    }
}

const TICK_EVENT_PREFIXES: &[&str] = &[
    "net/fabricmc/fabric/api/client/event/lifecycle/v1/ClientTickEvents",
    "net/minecraftforge/event/TickEvent",
    "net/neoforged/neoforge/client/event/ClientTickEvent",
    "net/minecraftforge/fml/common/gameevent/TickEvent",
];
const KEYBIND_PREFIXES: &[&str] = &[
    "net/fabricmc/fabric/api/client/keybinding/",
    "net/neoforged/neoforge/client/event/RegisterKeyMappingsEvent",
    "net/minecraftforge/client/event/RegisterKeyMappingsEvent",
    "net/minecraftforge/client/ClientRegistry",
];
const REFLECT_OWNERS: &[&str] = &["java/lang/Class", "java/lang/invoke/MethodHandles$Lookup"];
const REFLECT_NAMES: &[&str] = &[
    "getDeclaredField",
    "getField",
    "getDeclaredMethod",
    "getMethod",
    "forName",
    "findGetter",
    "findSetter",
    "findVirtual",
    "findStatic",
    "findStaticGetter",
    "findStaticSetter",
];
const MAPPING_RESOLVERS: &[&str] = &["net/fabricmc/loader/api/MappingResolver"];
const FRAMEWORK_PREFIXES: &[&str] = &[
    "net/minecraftforge/",
    "net/neoforged/",
    "net/fabricmc/",
    "org/spongepowered/",
    "cpw/mods/",
    "com/llamalad7/",
    "org/quiltmc/",
    "org/objectweb/asm/",
    "kotlin/",
    "kotlinx/",
    "org/jetbrains/",
    "com/google/",
    "org/apache/",
    "io/netty/",
    "it/unimi/",
    "org/lwjgl/",
    "org/slf4j/",
    "org/joml/",
    "com/electronwill/",
    "dev/architectury/",
    "com/mojang/",
    "net/minecraft/",
    "javax/",
    "com/sun/",
    "sun/",
    "org/openjdk/",
    "org/yaml/",
    "com/fasterxml/",
];
const VIA_REF_PREFIXES: &[&str] = &["com/viaversion/", "de/florianmichael/", "net/raphimc/"];
const USE_ITEM_EVENTS: &[&str] = &[
    "net/fabricmc/fabric/api/event/player/UseItemCallback",
    "net/minecraftforge/event/entity/player/PlayerInteractEvent$RightClickItem",
    "net/neoforged/neoforge/event/entity/player/PlayerInteractEvent$RightClickItem",
];
const DEATH_EVENTS: &[&str] = &[
    "net/fabricmc/fabric/api/entity/event/v1/ServerLivingEntityEvents",
    "net/minecraftforge/event/entity/living/LivingDeathEvent",
    "net/neoforged/neoforge/event/entity/living/LivingDeathEvent",
];
const NET_RECEIVER_PREFIXES: &[&str] = &[
    "net/fabricmc/fabric/api/networking/v1/ServerPlayNetworking",
    "net/fabricmc/fabric/api/client/networking/v1/ClientPlayNetworking",
    "net/minecraftforge/network/NetworkEvent",
    "net/minecraftforge/network/simple/SimpleChannel",
    "net/minecraftforge/event/network/CustomPayloadEvent",
    "net/neoforged/neoforge/network/handling/IPayloadContext",
    "net/neoforged/neoforge/network/registration/PayloadRegistrar",
    "net/neoforged/neoforge/network/handling/PlayPayloadContext",
];
const VIA_PREFIXES: &[&str] = &[
    "com/viaversion/",
    "de/florianmichael/viafabricplus/",
    "net/raphimc/vialoader/",
];
const MODIFY_ANN: &[&str] = &[
    "ModifyConstant",
    "ModifyArg",
    "ModifyArgs",
    "ModifyReturnValue",
    "ModifyExpressionValue",
    "ModifyVariable",
];
const MODIFYING: &[&str] = &[
    "@Inject(cancellable)",
    "@Redirect",
    "@ModifyReturnValue",
    "@ModifyConstant",
    "@ModifyArg",
    "@ModifyArgs",
    "@ModifyVariable",
    "@ModifyExpressionValue",
    "@WrapOperation",
    "@WrapWithCondition",
    "@Overwrite",
    "@WrapMethod",
];

fn in_list(s: &str, l: &[&str]) -> bool {
    l.contains(&s)
}

type OptStr = Option<String>;

#[derive(Clone, Debug, Default)]
struct Hook {
    owner: OptStr,
    name: String,
    ann: String,
    mmethod: String,
}
type Access = Hook;

#[derive(Clone, Debug, Default)]
struct WriteRec {
    owner: OptStr,
    name: String,
    src: String,
}
type WKey = (OptStr, String);

struct ClassEv {
    name: String,
    entry: String,
    is_mixin: bool,
    targets: BTreeSet<String>,
    refs: BTreeSet<String>,
    tokens: BTreeSet<String>,
    calls: Vec<Member>,
    hooks: Vec<Hook>,
    accesses: Vec<Access>,
    hints: StrList,
    modvals: StrList,
    mixin_methods: StrList,
    strings: StrList,
    idents: StrList,
    parse_ok: bool,
    writes: Vec<WriteRec>,
    modconsts: Vec<(StrList, Vec<i64>)>,
    reflective: bool,
    super_: String,
    bodies: Vec<Arc<MethodBody>>,
    method: String,
    indy_custom: i32,
    access_flags: i32,
    interfaces: StrList,
    wconst: BTreeMap<WKey, BTreeSet<OptInt>>,
}
impl ClassEv {
    fn new() -> ClassEv {
        ClassEv {
            name: String::new(),
            entry: String::new(),
            is_mixin: false,
            targets: BTreeSet::new(),
            refs: BTreeSet::new(),
            tokens: BTreeSet::new(),
            calls: Vec::new(),
            hooks: Vec::new(),
            accesses: Vec::new(),
            hints: Vec::new(),
            modvals: Vec::new(),
            mixin_methods: Vec::new(),
            strings: Vec::new(),
            idents: Vec::new(),
            parse_ok: true,
            writes: Vec::new(),
            modconsts: Vec::new(),
            reflective: false,
            super_: String::new(),
            bodies: Vec::new(),
            method: String::new(),
            indy_custom: 0,
            access_flags: 0,
            interfaces: Vec::new(),
            wconst: BTreeMap::new(),
        }
    }
}
type EvP = Arc<ClassEv>;

fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c >= 0x80
}

fn desc_classes<F: FnMut(&str)>(s: &str, mut cb: F) {
    let b = s.as_bytes();
    let n = b.len();
    let mut i = 0usize;
    let inset = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'$' || c == b'/';
    while i < n {
        if b[i] == b'L' {
            let mut j = i + 1;
            while j < n && inset(b[j]) {
                j += 1;
            }
            if j > i + 1 && j < n && b[j] == b';' {
                if let Some(x) = s.get(i + 1..j) {
                    cb(x);
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
}

fn inter_tokens<F: FnMut(&str)>(s: &str, mut cb: F) {
    let b = s.as_bytes();
    let n = b.len();
    const P: [&[u8]; 3] = [b"method_", b"field_", b"comp_"];
    let mut i = 0usize;
    while i < n {
        let c = b[i];
        if c != b'm' && c != b'f' && c != b'c' {
            i += 1;
            continue;
        }
        if i > 0 && is_word_byte(b[i - 1]) {
            i += 1;
            continue;
        }
        for p in P.iter() {
            if !b[i..].starts_with(p) {
                continue;
            }
            let j = i + p.len();
            let mut k = j;
            while k < n && b[k].is_ascii_digit() {
                k += 1;
            }
            if k == j {
                break;
            }
            if k < n && is_word_byte(b[k]) {
                break;
            }
            if let Some(x) = s.get(i..k) {
                cb(x);
            }
            i = k - 1;
            break;
        }
        i += 1;
    }
}

fn norm_target(v: &str) -> String {
    let mut s = pystrip(v);
    if s.is_empty() {
        return String::new();
    }
    if s.starts_with('L') && s.ends_with(';') && s.len() >= 2 {
        s = s[1..s.len() - 1].to_string();
    }
    replace_all(&s, ".", "/")
}

fn parse_member_string(s: &str, owner: &mut OptStr, name: &mut String) -> bool {
    *owner = None;
    name.clear();
    if s.is_empty() || s == "*" {
        return false;
    }
    let mut rest = s;
    let semi = s.find(';');
    let pre = first_seg(s, "(");
    if s.starts_with('L') && semi.is_some() {
        let semi = semi.unwrap_or(0);
        *owner = Some(s[1..semi].to_string());
        rest = &s[semi + 1..];
    } else if pre.contains('.') && pre.contains('/') {
        let d = pre.rfind('.').unwrap_or(0);
        *owner = Some(pre[..d].to_string());
        rest = &pre[d + 1..];
    }
    let k = rest.find(['(', ':']);
    let nm = pystrip(match k {
        None => rest,
        Some(k) => &rest[..k],
    });
    if nm.is_empty() {
        return false;
    }
    *name = nm;
    true
}

fn accessor_name(m: &str, ann: &str) -> String {
    let cut = |p: &str| -> String {
        let pl = p.len();
        if m.starts_with(p) && m.len() > pl {
            let n = &m[pl..];
            let mut it = n.chars();
            if let Some(f) = it.next() {
                let first = py_lower(&f.to_string());
                return first + it.as_str();
            }
        }
        String::new()
    };
    if ann.contains("Accessor") {
        for p in ["get", "set", "is"] {
            let r = cut(p);
            if !r.is_empty() {
                return r;
            }
        }
    }
    if ann.contains("Invoker") {
        for p in ["call", "invoke"] {
            let r = cut(p);
            if !r.is_empty() {
                return r;
            }
        }
    }
    m.to_string()
}

type Refmap = HashMap<String, HashMap<String, String>>;

fn mapped(vals: &[String], rm: &HashMap<String, String>, tokens: &mut BTreeSet<String>) -> StrList {
    let mut out = Vec::new();
    for v in vals {
        out.push(v.clone());
        if let Some(it) = rm.get(v) {
            out.push(it.clone());
            inter_tokens(it, |t| {
                tokens.insert(t.to_string());
            });
        }
    }
    out
}

fn flat(v: Option<&AV>) -> StrList {
    let mut o = Vec::new();
    flatten_values(v, &mut o);
    o
}

fn build_class_ev(entry: &str, data: &[u8], refmap: &Refmap) -> Result<EvP, ClassParseError> {
    let ci = parse_class(data)?;
    let mut ev = ClassEv::new();
    ev.name = if !ci.name.is_empty() {
        ci.name.clone()
    } else {
        entry
            .get(
                ..entry
                    .len()
                    .saturating_sub(6)
                    .min(if entry.len() >= 6 { entry.len() - 6 } else { 0 }),
            )
            .unwrap_or("")
            .to_string()
    };
    ev.entry = entry.to_string();
    ev.parse_ok = ci.parse_ok;
    ev.bodies = ci.bodies.clone();
    ev.indy_custom = ci.indy_custom;
    ev.access_flags = ci.access;
    for i in &ci.interfaces {
        if !i.is_empty() {
            ev.interfaces.push(i.clone());
        }
    }
    for c in &ci.class_refs {
        if c.starts_with('[') {
            desc_classes(c, |x| {
                ev.refs.insert(x.to_string());
            });
        } else {
            ev.refs.insert(c.clone());
        }
    }
    let mut refl = false;
    for m in &ci.member_refs {
        if (in_list(&m.owner, REFLECT_OWNERS) && in_list(&m.name, REFLECT_NAMES))
            || starts_any(&m.owner, MAPPING_RESOLVERS)
        {
            refl = true;
            break;
        }
    }
    ev.reflective = refl;
    for s in &ci.utf8 {
        desc_classes(s, |x| {
            ev.refs.insert(x.to_string());
        });
        if refl {
            inter_tokens(s, |t| {
                ev.tokens.insert(t.to_string());
            });
            if s.starts_with("net.minecraft.") || s.starts_with("net/minecraft/") {
                ev.refs.insert(first_seg(&replace_all(s, ".", "/"), "(").to_string());
            }
        }
    }
    if !ci.super_.is_empty() {
        ev.refs.insert(ci.super_.clone());
        ev.super_ = ci.super_.clone();
    }
    for w in &ci.field_writes {
        ev.writes.push(WriteRec {
            owner: Some(w.owner.clone()),
            name: w.name.clone(),
            src: "putfield".to_string(),
        });
    }
    for b in &ci.bodies {
        for pc in &b.put_c {
            ev.wconst
                .entry((Some(pc.0.owner.clone()), pc.0.name.clone()))
                .or_default()
                .insert(pc.1);
        }
    }
    for i in &ci.interfaces {
        if !i.is_empty() {
            ev.refs.insert(i.clone());
        }
    }
    for m in &ci.member_refs {
        ev.calls.push(Member {
            owner: m.owner.clone(),
            name: m.name.clone(),
            desc: m.desc.clone(),
        });
        ev.refs.insert(m.owner.clone());
    }
    ev.strings = ci.strings.clone();
    ev.idents.push(ev.name.clone());
    for m in &ci.methods {
        if !m.0.is_empty() {
            ev.idents.push(m.0.clone());
        }
    }
    for f in &ci.fields {
        if !f.0.is_empty() {
            ev.idents.push(f.0.clone());
        }
    }
    for x in &ev.idents {
        if !x.is_empty() {
            ev.hints.push(py_lower(x));
        }
    }
    for x in &ev.strings {
        if !x.is_empty() {
            ev.hints.push(py_lower(x));
        }
    }

    let empty: HashMap<String, String> = HashMap::new();
    let rm = refmap.get(&ev.name).unwrap_or(&empty);
    for a in &ci.class_annotations {
        if !a.r#type.is_empty() && a.r#type.ends_with("/mixin/Mixin;") {
            ev.is_mixin = true;
            for v in mapped(&flat(a.get("value")), rm, &mut ev.tokens) {
                let tg = norm_target(&v);
                if !tg.is_empty() {
                    ev.targets.insert(tg);
                }
            }
            for v in mapped(&flat(a.get("targets")), rm, &mut ev.tokens) {
                let tg = norm_target(&v);
                if !tg.is_empty() {
                    ev.targets.insert(tg);
                }
            }
        }
    }
    for t in &ev.targets {
        ev.refs.insert(t.clone());
    }

    for ma in &ci.method_annotations {
        let t = &ma.a.r#type;
        if t.is_empty() {
            continue;
        }
        let mut short_t = rpartition_tail(&rstrip(t, ";"), "/");
        let is_mix = t.contains("/spongepowered/asm/mixin/") || t.contains("/llamalad7/mixinextras/");
        if !is_mix {
            continue;
        }
        let mname = &ma.mname;
        if in_list(&short_t, MODIFY_ANN) {
            ev.modvals.push(format!("@{} -> {}", short_t, mname));
        }
        if short_t == "ModifyConstant" {
            let mut ints: Vec<i64> = Vec::new();
            let cst = ma.a.get("constant");
            let mut cl: Vec<Option<&AV>> = Vec::new();
            match cst {
                Some(c) if c.k == AvKind::List => {
                    for x in &c.list {
                        cl.push(Some(x.as_ref()));
                    }
                }
                _ => cl.push(cst),
            }
            for c in cl.into_iter().flatten() {
                if c.k == AvKind::Ann {
                    if let Some(v) = c.get("intValue") {
                        if v.k == AvKind::Int {
                            ints.push(v.iv);
                        }
                    }
                }
            }
            let mut targets: StrList = Vec::new();
            for v in mapped(&flat(ma.a.get("method")), rm, &mut ev.tokens) {
                let mut o = None;
                let mut nme = String::new();
                if parse_member_string(&v, &mut o, &mut nme) {
                    targets.push(nme);
                }
            }
            ev.modconsts.push((targets, ints));
        }
        if short_t == "Accessor" || short_t == "Invoker" {
            let vals = mapped(&flat(ma.a.get("value")), rm, &mut ev.tokens);
            let mut names: Vec<(OptStr, String)> = Vec::new();
            let mut addn = |o: OptStr, n: String| {
                if names.iter().any(|x| x.0 == o && x.1 == n) {
                    return;
                }
                names.push((o, n));
            };
            for v in &vals {
                let mut o = None;
                let mut n = String::new();
                if parse_member_string(v, &mut o, &mut n) {
                    addn(o, n);
                }
            }
            if vals.is_empty() {
                addn(None, accessor_name(mname, &short_t));
            }
            for on in &names {
                ev.accesses.push(Hook {
                    owner: on.0.clone(),
                    name: on.1.clone(),
                    ann: format!("@{}", short_t),
                    mmethod: mname.clone(),
                });
                if short_t == "Accessor" && ma.mdesc.ends_with(")V") && !ma.mdesc.starts_with("()") {
                    ev.writes.push(WriteRec {
                        owner: on.0.clone(),
                        name: on.1.clone(),
                        src: format!("@Accessor setter {}", mname),
                    });
                }
            }
            continue;
        }
        if short_t == "Shadow" {
            continue;
        }
        if short_t == "Overwrite" {
            ev.hooks.push(Hook {
                owner: None,
                name: mname.clone(),
                ann: "@Overwrite".to_string(),
                mmethod: mname.clone(),
            });
            continue;
        }
        if short_t == "Inject" {
            if let Some(c) = ma.a.get("cancellable") {
                if c.k == AvKind::Int && c.iv == 1 {
                    short_t = "Inject(cancellable)".to_string();
                }
            }
        }
        for v in mapped(&flat(ma.a.get("method")), rm, &mut ev.tokens) {
            let mut o = None;
            let mut n = String::new();
            if parse_member_string(&v, &mut o, &mut n) {
                ev.hooks.push(Hook {
                    owner: o,
                    name: n,
                    ann: format!("@{}", short_t),
                    mmethod: mname.clone(),
                });
            }
        }
        let at = ma.a.get("at");
        let mut at_list: Vec<&AV> = Vec::new();
        match at {
            Some(a) if a.k == AvKind::List => {
                for x in &a.list {
                    at_list.push(x.as_ref());
                }
            }
            Some(a) if a.k != AvKind::None => at_list.push(a),
            _ => {}
        }
        for a in at_list {
            if a.k == AvKind::Ann {
                for v in mapped(&flat(a.get("target")), rm, &mut ev.tokens) {
                    let mut o = None;
                    let mut n = String::new();
                    if parse_member_string(&v, &mut o, &mut n) {
                        ev.hooks.push(Hook {
                            owner: o,
                            name: n,
                            ann: format!("@{} @At", short_t),
                            mmethod: mname.clone(),
                        });
                    }
                }
            }
        }
        for v in mapped(&flat(ma.a.get("target")), rm, &mut ev.tokens) {
            let mut o = None;
            let mut n = String::new();
            if parse_member_string(&v, &mut o, &mut n) {
                ev.hooks.push(Hook {
                    owner: o,
                    name: n,
                    ann: format!("@{}", short_t),
                    mmethod: mname.clone(),
                });
            }
        }
        ev.mixin_methods.push(format!("@{} {}", short_t, mname));
    }
    Ok(Arc::new(ev))
}

struct Ctx {
    mixin_targets: HashMap<String, BTreeSet<String>>,
}
impl Ctx {
    fn new(evs: &[&ClassEv]) -> Ctx {
        let mut mixin_targets = HashMap::new();
        for e in evs {
            if e.is_mixin {
                mixin_targets.insert(e.name.clone(), e.targets.clone());
            }
        }
        Ctx { mixin_targets }
    }
    fn eff_intersects(&self, owner: Option<&str>, ev: &ClassEv, set: &HashSet<&str>) -> bool {
        match owner {
            None => ev.targets.iter().any(|t| set.contains(t.as_str())),
            Some(o) => {
                if let Some(t) = self.mixin_targets.get(o) {
                    set.contains(o) || t.iter().any(|x| set.contains(x.as_str()))
                } else {
                    set.contains(o)
                }
            }
        }
    }
    fn eff_min_in(&self, owner: Option<&str>, ev: &ClassEv, set: &HashSet<&str>) -> Option<String> {
        let mut cands: Vec<&str> = Vec::new();
        match owner {
            None => {
                for t in ev.targets.iter() {
                    cands.push(t.as_str());
                }
            }
            Some(o) => {
                cands.push(o);
                if let Some(t) = self.mixin_targets.get(o) {
                    for x in t.iter() {
                        cands.push(x.as_str());
                    }
                }
            }
        }
        cands
            .into_iter()
            .filter(|x| set.contains(*x))
            .min()
            .map(|s| s.to_string())
    }
    fn eff_owners(&self, owner: Option<&str>, ev: &ClassEv) -> BTreeSet<String> {
        match owner {
            None => ev.targets.clone(),
            Some(o) => {
                if let Some(t) = self.mixin_targets.get(o) {
                    let mut s = t.clone();
                    s.insert(o.to_string());
                    s
                } else {
                    let mut s = BTreeSet::new();
                    s.insert(o.to_string());
                    s
                }
            }
        }
    }
}

struct Hit {
    kind: &'static str,
    detail: String,
}
fn hit(k: &'static str, d: String) -> Option<Hit> {
    Some(Hit { kind: k, detail: d })
}

fn kinds_has(k: &[&str], x: &str) -> bool {
    k.contains(&x)
}

fn class_hit(ev: &ClassEv, concept: &str) -> Option<Hit> {
    let names = nm().cls(concept);
    if names.is_empty() {
        return None;
    }
    for r in &ev.refs {
        let inn = names.contains(r.as_str());
        let base = if inn { r.as_str() } else { first_seg(r, "$") };
        if inn || (names.contains(base) && r.contains('$')) {
            let src = if ev.targets.contains(r) {
                "mixin hedefi"
            } else {
                "sınıf referansı"
            };
            return hit("ref", format!("{} ({}) [{}]", short_cls(r), r, src));
        }
    }
    None
}

fn pick<'a, T>(
    items: &'a [T],
    key: impl Fn(&T) -> (Option<&str>, &str),
    ok: &impl Fn(Option<&str>, &str) -> bool,
    inter: &HashSet<&str>,
) -> Option<&'a T> {
    let mut best: Option<&'a T> = None;
    for it in items {
        let (o, n) = key(it);
        if ok(o, n) {
            if inter.contains(n) {
                return Some(it);
            }
            if best.is_none() {
                best = Some(it);
            }
        }
    }
    best
}

fn member_hit(ev: &ClassEv, concept: &str, kinds: &[&str], ctx: &Ctx) -> Option<Hit> {
    let idx = nm().mem(concept)?;
    let inter = &idx.inter;
    let names = &idx.names;
    let owners = &idx.owners;
    let ok = |owner: Option<&str>, name: &str| -> bool {
        if name.is_empty() {
            return false;
        }
        if inter.contains(name) {
            return true;
        }
        if names.contains(name) {
            return ctx.eff_intersects(owner, ev, owners);
        }
        false
    };
    let label = |owner: Option<&str>, name: &str| -> String {
        if inter.contains(name) {
            return format!("{} [{}]", readable_tok(name), name);
        }
        let first = ctx.eff_min_in(owner, ev, owners);
        let o = match first {
            None => "?".to_string(),
            Some(f) => short_cls(&f),
        };
        format!("{}.{}", o, name)
    };
    fn hk(x: &Hook) -> (Option<&str>, &str) {
        (x.owner.as_deref(), x.name.as_str())
    }
    if kinds_has(kinds, "hook") {
        if let Some(h) = pick(&ev.hooks, hk, &ok, inter) {
            return hit(
                "hook",
                format!(
                    "{} -> {}  (mixin metodu: {})",
                    h.ann,
                    label(h.owner.as_deref(), &h.name),
                    h.mmethod
                ),
            );
        }
    }
    if kinds_has(kinds, "mod") {
        let mut mods: Vec<Hook> = Vec::new();
        for x in &ev.hooks {
            let parts = split_ws(&x.ann);
            if !parts.is_empty() && in_list(&parts[0], MODIFYING) {
                mods.push(x.clone());
            }
        }
        if let Some(h) = pick(&mods, hk, &ok, inter) {
            return hit(
                "mod",
                format!(
                    "{} -> {}  (mixin metodu: {}; sonucu değiştiriyor)",
                    h.ann,
                    label(h.owner.as_deref(), &h.name),
                    h.mmethod
                ),
            );
        }
    }
    if kinds_has(kinds, "access") {
        if let Some(a) = pick(&ev.accesses, hk, &ok, inter) {
            return hit(
                "access",
                format!(
                    "{} -> {}  (metot: {})",
                    a.ann,
                    label(a.owner.as_deref(), &a.name),
                    a.mmethod
                ),
            );
        }
    }
    fn wk(x: &WriteRec) -> (Option<&str>, &str) {
        (x.owner.as_deref(), x.name.as_str())
    }
    if kinds_has(kinds, "write") {
        if let Some(w) = pick(&ev.writes, wk, &ok, inter) {
            return hit(
                "write",
                format!("alana YAZMA ({}): {}", w.src, label(w.owner.as_deref(), &w.name)),
            );
        }
    }
    if kinds_has(kinds, "write0") {
        let mut zs: Vec<WriteRec> = Vec::new();
        for x in &ev.writes {
            let z = match ev.wconst.get(&(x.owner.clone(), x.name.clone())) {
                None => !x.src.starts_with("putfield"),
                Some(set) => set.iter().any(|c| match c {
                    None => true,
                    Some(v) => *v == 0 || *v == 1,
                }),
            };
            if z {
                zs.push(x.clone());
            }
        }
        if let Some(w) = pick(&zs, wk, &ok, inter) {
            let mut cs: BTreeSet<OptInt> = BTreeSet::new();
            match ev.wconst.get(&(w.owner.clone(), w.name.clone())) {
                Some(s) if !s.is_empty() => cs = s.clone(),
                _ => {
                    cs.insert(None);
                }
            }
            let mut vals: StrList = cs
                .iter()
                .map(|c| match c {
                    Some(v) => v.to_string(),
                    None => "ayardan/hesaplanan".to_string(),
                })
                .collect();
            vals.sort();
            return hit(
                "write",
                format!(
                    "alana YAZMA ({}): {} = {}",
                    w.src,
                    label(w.owner.as_deref(), &w.name),
                    join(&vals, ", ")
                ),
            );
        }
    }
    if kinds_has(kinds, "call") {
        fn ck(x: &Member) -> (Option<&str>, &str) {
            (Some(x.owner.as_str()), x.name.as_str())
        }
        if let Some(c) = pick(&ev.calls, ck, &ok, inter) {
            return hit("call", format!("çağrı/erişim: {}", label(Some(&c.owner), &c.name)));
        }
    }
    if kinds_has(kinds, "token") {
        for t in &ev.tokens {
            if inter.contains(t.as_str()) {
                return hit("token", format!("intermediary kimliği: {} [{}]", readable_tok(t), t));
            }
        }
    }
    None
}

const PLAYER_ROT_FIELDS: &[&str] = &["field_6031", "field_5965", "yaw", "pitch", "yRot", "xRot"];

fn player_rotate_hit(ev: &ClassEv, ctx: Option<&Ctx>) -> Option<Hit> {
    let players = &nm().players;
    let rot = &nm().rot;
    let is_player = |owner: &str| -> bool {
        if players.contains(owner) {
            return true;
        }
        if let Some(ctx) = ctx {
            if let Some(it) = ctx.mixin_targets.get(owner) {
                return it.iter().any(|t| players.contains(t.as_str()));
            }
        }
        false
    };
    for c in &ev.calls {
        if rot.contains(c.name.as_str()) && is_player(&c.owner) {
            return hit(
                "call",
                format!(
                    "OYUNCUNUN bakış yönü değiştiriliyor: {}.{}",
                    short_cls(&c.owner),
                    readable_tok(&c.name)
                ),
            );
        }
    }
    for w in &ev.writes {
        if PLAYER_ROT_FIELDS.contains(&w.name.as_str()) {
            if let Some(o) = &w.owner {
                if is_player(o) {
                    return hit(
                        "call",
                        format!(
                            "OYUNCUNUN bakış alanına yazılıyor ({}): {}.{}",
                            w.src,
                            short_cls(o),
                            readable_tok(&w.name)
                        ),
                    );
                }
            }
        }
    }
    let lp = nm().cls("C_LOOK_PKT");
    for c in &ev.calls {
        if c.name == "<init>" && lp.contains(c.owner.as_str()) {
            return hit(
                "call",
                format!("kodla bakış paketi üretiliyor: new {}(...)", short_cls(&c.owner)),
            );
        }
    }
    None
}

fn ref_pfx(ev: &ClassEv, pf: &[&str], what: &str) -> Option<Hit> {
    for r in &ev.refs {
        if starts_any(r, pf) {
            return hit("ref", format!("{}{}", what, r));
        }
    }
    None
}

fn special_hit(ev: &ClassEv, concept: &str, ctx: Option<&Ctx>) -> Option<Hit> {
    if concept == "X_PLAYER_ROTATE" {
        return player_rotate_hit(ev, ctx);
    }
    if let Some(w) = concept.strip_prefix("S:") {
        for h in &ev.hints {
            if h.contains(w) {
                return hit("hint", format!("ipucu '{}' -> \"{}\"", w, uslice(h, 80)));
            }
        }
        return None;
    }
    if concept == "X_SORT" {
        for c in &ev.calls {
            if c.owner.starts_with("java/util/Comparator")
                || ((c.name == "sort" || c.name == "sorted")
                    && (c.owner.starts_with("java/util/") || c.owner.starts_with("java/util/stream/")))
            {
                return hit("call", format!("java sıralama: {}.{}", last_seg(&c.owner, "/"), c.name));
            }
        }
        return None;
    }
    if concept == "X_TIMER" {
        for c in &ev.calls {
            if (c.owner == "java/lang/System" && (c.name == "currentTimeMillis" || c.name == "nanoTime"))
                || c.owner == "java/util/Random"
                || c.owner == "java/util/concurrent/ThreadLocalRandom"
                || c.owner == "java/security/SecureRandom"
            {
                return hit(
                    "call",
                    format!("zamanlayıcı/rastgele: {}.{}", last_seg(&c.owner, "/"), c.name),
                );
            }
        }
        return None;
    }
    if concept == "X_TICK_EVENT" {
        return ref_pfx(ev, TICK_EVENT_PREFIXES, "tick olayı: ");
    }
    if concept == "X_KEYBIND_API" {
        return ref_pfx(ev, KEYBIND_PREFIXES, "tuş atama API: ");
    }
    if concept == "X_NEW_BLOCKHIT" {
        let bh = nm().cls("C_BLOCK_HIT");
        for c in &ev.calls {
            if c.name == "<init>" && bh.contains(c.owner.as_str()) {
                return hit("call", format!("new {}(...)", short_cls(&c.owner)));
            }
        }
        return None;
    }
    if concept == "X_MODIFY_VALUE" {
        if let Some(m) = ev.modvals.first() {
            return hit("ref", m.clone());
        }
        return None;
    }
    if concept == "X_NEW_MOVE_PKT" {
        let mp = nm().cls("C_MOVE_PKT");
        for c in &ev.calls {
            if c.name == "<init>" && mp.contains(c.owner.as_str()) {
                return hit(
                    "call",
                    format!("kodla hareket paketi üretme: new {}(...)", short_cls(&c.owner)),
                );
            }
        }
        return None;
    }
    if concept == "X_ATAN2" {
        let mh = nm().cls("C_MATH_HELPER");
        for c in &ev.calls {
            if c.name == "atan2" && (c.owner == "java/lang/Math" || c.owner == "java/lang/StrictMath") {
                return hit("call", "açı hesabı: Math.atan2".to_string());
            }
            if mh.contains(c.owner.as_str()) && (c.name == "atan2" || c.name == "method_15349") {
                return hit("call", "açı hesabı: MathHelper.atan2".to_string());
            }
        }
        return None;
    }
    if concept == "X_FAKE_PLAYER" {
        if !ev.super_.is_empty() && nm().cls("C_CLIENT_PLAYER_BASES").contains(ev.super_.as_str()) {
            return hit(
                "ref",
                format!("kendi oyuncu/kamera varlığı ({} alt sınıfı)", short_cls(&ev.super_)),
            );
        }
        return None;
    }
    if concept == "X_USE_ITEM_EVENT" {
        return ref_pfx(ev, USE_ITEM_EVENTS, "eşya kullanma olayı: ");
    }
    if concept == "X_DEATH_EVENT" {
        return ref_pfx(ev, DEATH_EVENTS, "ölüm olayı: ");
    }
    if concept == "X_NEW_RAYCAST_CTX" {
        let rc = nm().cls("C_RAYCAST_CTX");
        for c in &ev.calls {
            if c.name == "<init>" && rc.contains(c.owner.as_str()) {
                return hit(
                    "call",
                    format!("kendi blok işin-izlemesi: new {}(...)", short_cls(&c.owner)),
                );
            }
        }
        return None;
    }
    if concept == "X_JUMP_CONST" {
        let tick = nm().mem("M_TICK_MOVEMENT")?;
        for mc in &ev.modconsts {
            let has10 = mc.1.contains(&10i64);
            let tgt =
                mc.0.iter()
                    .any(|t| tick.inter.contains(t.as_str()) || tick.names.contains(t.as_str()));
            if has10 && tgt {
                return hit(
                    "hook",
                    "@ModifyConstant: tickMovement içindeki 10 (zıplama bekleme süresi) değiştiriliyor".to_string(),
                );
            }
        }
        return None;
    }
    if concept == "X_RAW_KEY" {
        if let Some(ctx) = ctx {
            if let Some(h) = member_hit(ev, "M_INPUT_IS_KEY_PRESSED", &["call"], ctx) {
                return hit("call", h.detail);
            }
        }
        for c in &ev.calls {
            if c.owner == "org/lwjgl/glfw/GLFW" && (c.name == "glfwGetKey" || c.name == "glfwGetMouseButton") {
                return hit("call", format!("fiziksel tuş okuma: GLFW.{}", c.name));
            }
        }
        return None;
    }
    if concept == "X_LOOP" {
        for b in &ev.bodies {
            if b.r#loop {
                let n = if b.name.is_empty() { "?" } else { b.name.as_str() };
                return hit("call", format!("döngü (tekrar eden işlem): {}", n));
            }
        }
        return None;
    }
    if concept == "X_MOVE_KEYS" {
        if let Some(ctx) = ctx {
            if member_hit(ev, "F_ALL_KEYS", &["call"], ctx).is_some() {
                return hit(
                    "call",
                    "TÜM tuş atamaları tek tek işleniyor (KeyBinding.KEYS_BY_ID)".to_string(),
                );
            }
        }
        let idx = nm().mem("F_MOVE_KEYS")?;
        let mut got: BTreeSet<&str> = BTreeSet::new();
        for c in &ev.calls {
            if idx.inter.contains(c.name.as_str()) {
                got.insert(c.name.as_str());
            } else if idx.names.contains(c.name.as_str()) {
                if let Some(ctx) = ctx {
                    if ctx.eff_intersects(Some(&c.owner), ev, &idx.owners) {
                        got.insert(c.name.as_str());
                    }
                }
            }
        }
        if got.len() >= 3 {
            let mut r: StrList = Vec::new();
            for g in &got {
                if r.len() >= 6 {
                    break;
                }
                r.push(readable_tok(g));
            }
            return hit("call", format!("hareket tuşları: {}", join(&r, ", ")));
        }
        return None;
    }
    if concept == "X_INPUT_WRITE" {
        let kb = &nm().kb_input;
        for w in &ev.writes {
            let inter = match ctx {
                Some(ctx) => ctx.eff_intersects(w.owner.as_deref(), ev, kb),
                None => w.owner.as_deref().is_some_and(|o| kb.contains(o)),
            };
            if inter {
                return hit(
                    "write",
                    format!("hareket girdisine YAZMA ({}): Input.{}", w.src, w.name),
                );
            }
        }
        return None;
    }
    if concept == "X_NET_RECEIVER" {
        return ref_pfx(ev, NET_RECEIVER_PREFIXES, "ağ paketi alıcısı: ");
    }
    if concept == "X_VIA_COMPAT" {
        return ref_pfx(ev, VIA_PREFIXES, "sürüm uyumluluk katmanı: ");
    }
    None
}

fn concept_hit(ev: &ClassEv, concept: &str, kinds: &[&str], ctx: &Ctx) -> Option<Hit> {
    if concept.starts_with("S:") || concept.starts_with("X_") {
        let h = special_hit(ev, concept, Some(ctx))?;
        if kinds_has(kinds, h.kind) {
            return Some(h);
        }
        return None;
    }
    if concept.starts_with("C_") {
        return if kinds_has(kinds, "ref") {
            class_hit(ev, concept)
        } else {
            None
        };
    }
    member_hit(ev, concept, kinds, ctx)
}

fn mkey(a: &str, b: &str, c: &str) -> String {
    format!("{}\x1f{}\x1f{}", a, b, c)
}

type CB = (usize, usize);

struct MethodIndex<'a> {
    evs: &'a [&'a ClassEv],
    by_class: HashMap<String, usize>,
    methods: HashMap<String, CB>,
    by_name: HashMap<String, Vec<CB>>,
    cache: HashMap<String, Vec<CB>>,
}

impl<'a> MethodIndex<'a> {
    fn new(evs: &'a [&'a ClassEv]) -> Self {
        let mut by_class = HashMap::new();
        for (i, e) in evs.iter().enumerate() {
            by_class.insert(e.name.clone(), i);
        }
        let mut methods = HashMap::new();
        let mut by_name: HashMap<String, Vec<CB>> = HashMap::new();
        for (i, e) in evs.iter().enumerate() {
            for (j, b) in e.bodies.iter().enumerate() {
                methods.insert(mkey(&e.name, &b.name, &b.desc), (i, j));
                by_name
                    .entry(format!("{}\x1f{}", e.name, b.name))
                    .or_default()
                    .push((i, j));
            }
        }
        MethodIndex {
            evs,
            by_class,
            methods,
            by_name,
            cache: HashMap::new(),
        }
    }

    fn body(&self, cb: CB) -> &'a MethodBody {
        let evs: &'a [&'a ClassEv] = self.evs;
        &evs[cb.0].bodies[cb.1]
    }

    fn chain(&mut self, cls: usize, bi: usize) -> Vec<CB> {
        let evs = self.evs;
        let key = {
            let b = &evs[cls].bodies[bi];
            mkey(&evs[cls].name, &b.name, &b.desc)
        };
        if let Some(c) = self.cache.get(&key) {
            return c.clone();
        }
        let mut out: Vec<CB> = vec![(cls, bi)];
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert(key.clone());
        let mut frontier: Vec<CB> = vec![(cls, bi)];
        for _depth in 0..3 {
            let mut nxt: Vec<CB> = Vec::new();
            for fb in &frontier {
                let ce = evs[fb.0];
                let b = &ce.bodies[fb.1];
                let mut targets: Vec<Member> = b.invokes.clone();
                for ind in &b.indy {
                    if ind.has_impl && !ind.r#impl.owner.is_empty() {
                        targets.push(ind.r#impl.clone());
                    }
                }
                for t in &targets {
                    if !self.by_class.contains_key(&t.owner) {
                        continue;
                    }
                    let mut cands: Vec<CB> = Vec::new();
                    if let Some(h) = self.methods.get(&mkey(&t.owner, &t.name, &t.desc)) {
                        cands.push(*h);
                    } else if let Some(bn) = self.by_name.get(&format!("{}\x1f{}", t.owner, t.name)) {
                        cands.extend(bn.iter().take(2).copied());
                    }
                    for c in &cands {
                        let cbody = &evs[c.0].bodies[c.1];
                        let k = mkey(&evs[c.0].name, &cbody.name, &cbody.desc);
                        if !seen.contains(&k) && out.len() < MAX_CHAIN {
                            seen.insert(k);
                            out.push(*c);
                            nxt.push(*c);
                        }
                    }
                }
                let outer = format!("{}$", first_seg(&ce.name, "$"));
                for nc in &b.news {
                    let Some(&bc) = self.by_class.get(nc) else { continue };
                    if !nc.starts_with(&outer) {
                        continue;
                    }
                    for (nbi, nb) in evs[bc].bodies.iter().enumerate() {
                        let k = mkey(nc, &nb.name, &nb.desc);
                        if !seen.contains(&k) && out.len() < MAX_CHAIN {
                            seen.insert(k);
                            out.push((bc, nbi));
                            nxt.push((bc, nbi));
                        }
                    }
                }
            }
            frontier = nxt;
            if frontier.is_empty() {
                break;
            }
        }
        self.cache.insert(key, out.clone());
        out
    }
}

fn chain_ev(idx: &mut MethodIndex, cls: usize, bi: usize) -> EvP {
    let chain = idx.chain(cls, bi);
    let evs = idx.evs;
    let cls_ev = evs[cls];
    let body = &cls_ev.bodies[bi];
    let mut ev = ClassEv::new();
    ev.name = cls_ev.name.clone();
    ev.entry = cls_ev.entry.clone();
    ev.method = format!("{}.{}", rpartition_tail(&dotted(&cls_ev.name), "."), body.name);
    ev.is_mixin = cls_ev.is_mixin;
    ev.targets = cls_ev.targets.clone();
    ev.super_ = cls_ev.super_.clone();
    ev.reflective = cls_ev.reflective;
    ev.modvals = cls_ev.modvals.clone();
    ev.parse_ok = cls_ev.parse_ok;
    ev.refs = cls_ev.targets.clone();
    for cb in &chain {
        let b = &evs[cb.0].bodies[cb.1];
        for m in &b.invokes {
            ev.calls.push(m.clone());
            ev.refs.insert(m.owner.clone());
        }
        for m in &b.gets {
            ev.calls.push(m.clone());
            ev.refs.insert(m.owner.clone());
        }
        for m in &b.puts {
            ev.writes.push(WriteRec {
                owner: Some(m.owner.clone()),
                name: m.name.clone(),
                src: "putfield".to_string(),
            });
            ev.refs.insert(m.owner.clone());
        }
        for pc in &b.put_c {
            ev.wconst
                .entry((Some(pc.0.owner.clone()), pc.0.name.clone()))
                .or_default()
                .insert(pc.1);
        }
        for n in &b.news {
            ev.refs.insert(n.clone());
        }
        for t in &b.types {
            ev.refs.insert(t.clone());
        }
        ev.strings.extend(b.strs.iter().cloned());
        for ind in &b.indy {
            if ind.has_impl && !ind.r#impl.owner.is_empty() {
                ev.calls.push(ind.r#impl.clone());
                ev.refs.insert(ind.r#impl.owner.clone());
            }
        }
    }
    ev.idents = vec![body.name.clone()];
    for s in &ev.strings {
        if !s.is_empty() {
            ev.hints.push(py_lower(s));
        }
    }
    for cb in &chain {
        ev.bodies.push(evs[cb.0].bodies[cb.1].clone());
    }
    for cb in &chain {
        let Some(&it) = idx.by_class.get(&evs[cb.0].name) else {
            continue;
        };
        let mname = &evs[cb.0].bodies[cb.1].name;
        for h in &evs[it].hooks {
            if h.mmethod == *mname {
                ev.hooks.push(h.clone());
            }
        }
    }
    let mut setter_c: BTreeMap<(String, String), BTreeSet<OptInt>> = BTreeMap::new();
    for cb in &chain {
        for ic in &evs[cb.0].bodies[cb.1].inv_c {
            setter_c
                .entry((ic.0.owner.clone(), ic.0.name.clone()))
                .or_default()
                .insert(ic.1);
        }
    }
    let ncalls = ev.calls.len();
    for k in 0..ncalls {
        let c = ev.calls[k].clone();
        let Some(&it) = idx.by_class.get(&c.owner) else {
            continue;
        };
        let acc = evs[it];
        if !acc.is_mixin {
            continue;
        }
        for a in &acc.accesses {
            if a.mmethod == c.name {
                ev.accesses.push(a.clone());
            }
        }
        for w in &acc.writes {
            if w.src.ends_with(&format!(" {}", c.name)) {
                ev.writes.push(w.clone());
                let dst = ev.wconst.entry((w.owner.clone(), w.name.clone())).or_default();
                match setter_c.get(&(c.owner.clone(), c.name.clone())) {
                    Some(sc) => dst.extend(sc.iter().copied()),
                    None => {
                        dst.insert(None);
                    }
                }
            }
        }
    }
    if !ev.hooks.is_empty() {
        ev.modconsts = cls_ev.modconsts.clone();
    }
    if cls_ev.reflective {
        ev.tokens = cls_ev.tokens.clone();
    }
    Arc::new(ev)
}

fn match_groups(groups: &[SigGroup], exclude: SigGroup, evs: &[&ClassEv], ctx: &Ctx, out: &mut Vec<RowGroup>) -> bool {
    out.clear();
    for alt in exclude.iter() {
        for e in evs {
            if concept_hit(e, alt.concept, alt.kinds, ctx).is_some() {
                return false;
            }
        }
    }
    for group in groups {
        let mut found: RowGroup = Vec::new();
        for alt in group.iter() {
            for e in evs {
                if let Some(h) = concept_hit(e, alt.concept, alt.kinds, ctx) {
                    found.push(Row {
                        kind: h.kind.to_string(),
                        detail: h.detail,
                        cls: e.name.clone(),
                        concept: alt.concept.to_string(),
                    });
                    break;
                }
            }
            if found.len() >= 3 {
                break;
            }
        }
        if found.is_empty() {
            return false;
        }
        out.push(found);
    }
    true
}

macro_rules! rx_static {
    ($name:ident, $pat:expr, $flags:expr) => {
        fn $name() -> &'static Rx {
            static R: OnceLock<Rx> = OnceLock::new();
            R.get_or_init(|| Rx::new($pat, $flags))
        }
    };
}
rx_static!(rx_toml_modid, r#"modId\s*=\s*"([^"]+)""#, 0);
rx_static!(rx_toml_name, r#"displayName\s*=\s*"([^"]+)""#, 0);
rx_static!(rx_toml_ver, r#"version\s*=\s*"([^"]+)""#, 0);
rx_static!(rx_toml_client1, r#"clientSideOnly\s*=\s*true"#, 0);
rx_static!(rx_toml_client2, r#"displayTest\s*=\s*"IGNORE_(ALL|SERVER)_VERSION""#, 0);
rx_static!(rx_fmj_id, r#""id"\s*:\s*"([^"]+)""#, Rx::BYTES);
rx_static!(
    rx_agent,
    r#"^(Premain-Class|Agent-Class|Launcher-Agent-Class)\s*:\s*(\S+)"#,
    Rx::M
);
rx_static!(rx_main_class, r#"^Main-Class\s*:\s*([A-Za-z0-9_.$]+)"#, Rx::M);
rx_static!(rx_via, r#"via(version|backwards|rewind|legacy|loader)"#, 0);
rx_static!(rx_src_pkg, r#"^\s*package\s+([A-Za-z_][\w.]*)\s*;?"#, Rx::M | Rx::BYTES);
rx_static!(rx_stem1, r#"^(module|hack|feature|function|cheat)(?=[a-z]{3})"#, 0);
rx_static!(rx_stem2, r#"(module|hack|feature|function|cheat|mod|impl)$"#, 0);

type Files = Vec<(String, Bytes)>;
fn fget<'a>(f: &'a Files, n: &str) -> Option<&'a Bytes> {
    f.iter().rev().find(|kv| kv.0 == n).map(|kv| &kv.1)
}

fn obj_of(j: &Option<JPtr>) -> Option<&JVal> {
    j.as_deref().filter(|v| v.is_obj())
}

fn parse_meta(files: &Files) -> ModMeta {
    let mut meta = ModMeta::default();
    if let Some(fmj) = fget(files, "fabric.mod.json") {
        let j = read_json_bytes(fmj);
        let o = obj_of(&j);
        meta.loader.set_str("Fabric");
        meta.id.set_json(jget(o, "id"));
        meta.name.set_json(jget(o, "name"));
        meta.version.set_json(jget(o, "version"));
        meta.description.set_json(jget(o, "description"));
        meta.environment.set_json(jget(o, "environment"));
        if let Some(auth) = jget(o, "authors") {
            if auth.is_arr() {
                for a in &auth.arr {
                    if a.is_str() {
                        meta.authors.push(a.s.clone());
                    } else if a.is_obj() {
                        meta.authors.push(jstr(a.get("name")));
                    } else {
                        meta.authors.push(String::new());
                    }
                }
            }
        }
        if let Some(mx) = jget(o, "mixins") {
            if mx.is_arr() {
                for m in &mx.arr {
                    if m.is_str() {
                        meta.mixin_configs.push(m.s.clone());
                    } else if m.is_obj() {
                        meta.mixin_configs.push(jstr(m.get("config")));
                    } else {
                        meta.mixin_configs.push(String::new());
                    }
                }
            }
        }
        if !meta.id.truthy {
            if let Some(m) = rx_fmj_id().search(fmj, 0) {
                meta.id.set_str(&utf8_decode(m.group_bytes(1), 0));
            } else {
                meta.id.clear();
                meta.id.present = true;
            }
        }
    }
    if let Some(qmj) = fget(files, "quilt.mod.json") {
        if !meta.id.truthy {
            let j = read_json_bytes(qmj);
            let o = obj_of(&j);
            let ql = jget(o, "quilt_loader").filter(|v| v.is_obj());
            meta.loader.set_str("Quilt");
            meta.id.set_json(jget(ql, "id"));
            meta.version.set_json(jget(ql, "version"));
            let md = jget(ql, "metadata");
            meta.name.set_json(match md {
                Some(md) if md.is_obj() => md.get("name"),
                _ => None,
            });
        }
    }
    for toml in ["META-INF/neoforge.mods.toml", "META-INF/mods.toml"] {
        if let Some(tb) = fget(files, toml) {
            if !meta.id.truthy {
                let t = utf8_decode(tb, 1);
                let tbytes = t.as_bytes();
                meta.loader
                    .set_str(if toml.contains("neoforge") { "NeoForge" } else { "Forge" });
                if let Some(m) = rx_toml_modid().search(tbytes, 0) {
                    meta.id.set_str(&m.group(1));
                } else {
                    meta.id.clear();
                    meta.id.present = true;
                }
                if let Some(m) = rx_toml_name().search(tbytes, 0) {
                    meta.name.set_str(&m.group(1));
                } else {
                    meta.name.clear();
                }
                if let Some(m) = rx_toml_ver().search(tbytes, 0) {
                    meta.version.set_str(&m.group(1));
                } else {
                    meta.version.clear();
                }
                if rx_toml_client1().search(tbytes, 0).is_some() || rx_toml_client2().search(tbytes, 0).is_some() {
                    meta.environment.set_str("client");
                }
            }
        }
    }
    meta
}

fn client_mixins(files: &Files, meta: &ModMeta) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut cfgs: BTreeSet<String> = BTreeSet::new();
    for c in &meta.mixin_configs {
        if !c.is_empty() {
            cfgs.insert(c.clone());
        }
    }
    for kv in files {
        let l = py_lower(&kv.0);
        if kv.0.ends_with(".json") && l.contains("mixin") && !l.contains("refmap") {
            cfgs.insert(kv.0.clone());
        }
    }
    for cfg in &cfgs {
        let Some(b) = fget(files, cfg) else { continue };
        let j = read_json_bytes(b);
        let o = obj_of(&j);
        let pkg = replace_all(&jstr(jget(o, "package")), ".", "/");
        if let Some(cl) = jget(o, "client") {
            if cl.is_arr() {
                for n in &cl.arr {
                    if n.is_str() {
                        let nn = replace_all(&n.s, ".", "/");
                        out.insert(if pkg.is_empty() { nn } else { format!("{}/{}", pkg, nn) });
                    }
                }
            }
        }
    }
    out
}

fn load_refmaps(files: &Files, meta: &ModMeta) -> Refmap {
    let mut out: Refmap = HashMap::new();
    let mut cand: BTreeSet<String> = BTreeSet::new();
    for cfg in &meta.mixin_configs {
        if cfg.is_empty() {
            continue;
        }
        let Some(b) = fget(files, cfg) else { continue };
        let j = read_json_bytes(b);
        let o = obj_of(&j);
        if let Some(r) = jget(o, "refmap") {
            if r.truthy() && r.is_str() {
                cand.insert(r.s.clone());
            }
        }
    }
    for kv in files {
        if kv.0.ends_with(".json") && py_lower(&kv.0).contains("refmap") {
            cand.insert(kv.0.clone());
        }
    }
    for n in &cand {
        let Some(b) = fget(files, n) else { continue };
        let j = read_json_bytes(b);
        let o = obj_of(&j);
        let mut blocks: Vec<&JVal> = Vec::new();
        if let Some(mp) = jget(o, "mappings") {
            if mp.is_obj() {
                blocks.push(mp);
            }
        }
        if let Some(dt) = jget(o, "data") {
            if dt.is_obj() {
                for kv in &dt.obj {
                    if kv.1.is_obj() {
                        blocks.push(kv.1.as_ref());
                    }
                }
            }
        }
        for blk in blocks {
            for kv in &blk.obj {
                if kv.1.is_obj() {
                    let dst = out.entry(kv.0.clone()).or_default();
                    for kv2 in &kv.1.obj {
                        if kv2.1.is_str() {
                            dst.insert(kv2.0.clone(), kv2.1.s.clone());
                        }
                    }
                }
            }
        }
    }
    out
}

const MC_MARKERS: &[&str] = &[
    "net/minecraft/",
    "net.minecraft.",
    "com/mojang/",
    "net/fabricmc/",
    "cpw/mods/",
    "net/minecraftforge/",
    "net/neoforged/",
    "org/spongepowered/asm/mixin",
];
fn has_mc_marker(b: &[u8]) -> bool {
    MC_MARKERS.iter().any(|m| bcontains(b, m.as_bytes()))
}
const INJECT_MARKERS: &[&str] = &[
    "com/sun/tools/attach/",
    "java/lang/instrument/",
    "com.sun.tools.attach",
    "net/bytebuddy/agent/",
];
const LOADER_AUX: &[&str] = &[
    "defineclass",
    "javax/crypto/cipher",
    "java/net/",
    "minecraft",
    "javaw",
    "lwjgl",
];
const LEGIT_AGENT_PKGS: &[&str] = &[
    "moe/yushi/authlibinjector",
    "org/jacoco/",
    "com/intellij/",
    "com/jetbrains/",
    "com/yourkit/",
    "com/jprofiler/",
    "com/ejt/",
    "org/netbeans/",
    "org/openjdk/jmc/",
    "io/opentelemetry/",
    "co/elastic/apm/",
    "com/newrelic/",
    "com/datadog/",
    "datadog/",
    "org/eclipse/",
    "lombok/",
    "com/sun/btrace/",
    "org/openjdk/btrace/",
    "com/taobao/arthas/",
    "kotlinx/coroutines/debug/",
    "org/mockito/",
    "net/bytebuddy/agent/Installer",
];
const GAME_TARGET_WORDS: &[&str] = &[
    "minecraft",
    "javaw",
    "lwjgl",
    "net.minecraft",
    "net/minecraft",
    "lunarclient",
    "lunar client",
    "feather",
    "badlion",
    "labymod",
    "fabricmc",
    "minecraftforge",
    "neoforged",
    "optifine",
    "tlauncher",
    "pojav",
    "glfw",
];
const SERVER_API_PREFIXES: &[&str] = &[
    "org/bukkit/",
    "io/papermc/",
    "org/spigotmc/",
    "net/md_5/bungee/",
    "com/velocitypowered/",
    "com/destroystokyo/paper/",
    "net/kyori/adventure/platform/bukkit",
];
const CLIENT_ONLY_PREFIXES: &[&str] = &["net/minecraft/client/", "com/mojang/blaze3d/", "org/lwjgl/"];
const SERVER_PLUGIN_FILES: &[&str] = &["plugin.yml", "paper-plugin.yml", "bungee.yml", "velocity-plugin.json"];

const SERVER_BOOTSTRAP_MAINS: &[&str] = &[
    "io/papermc/paperclip/main",
    "io/papermc/paperclip/paperclip",
    "org/bukkit/craftbukkit/main",
    "org/bukkit/craftbukkit/bootstrap/main",
    "net/minecraft/server/main",
    "net/minecraft/bundler/main",
    "com/velocitypowered/proxy/velocity",
    "net/md_5/bungee/bootstrap",
];
const SERVER_BOOTSTRAP_CLASSES: &[&str] = &[
    "io/papermc/paperclip/Paperclip",
    "io/papermc/paperclip/Main",
    "org/bukkit/craftbukkit/Main",
    "net/minecraft/server/MinecraftServer",
    "com/velocitypowered/proxy/Velocity",
    "net/md_5/bungee/BungeeCord",
    "net/md_5/bungee/Bootstrap",
];
const SERVER_CLIENT_DISQUALIFY: &[&str] = &[
    "net/minecraft/client/",
    "com/mojang/blaze3d/",
    "org/lwjgl/",
    "net/minecraft/class_",
    "Lorg/spongepowered/asm/mixin/Mixin;",
    "org/spongepowered/asm/mixin/injection/",
    "net/fabricmc/",
    "net/minecraftforge/",
    "net/neoforged/",
    "cpw/mods/",
    "org/quiltmc/",
];

fn add_finding(
    res: &mut ScanResult,
    key: &str,
    label: &str,
    category: &str,
    explain: &str,
    rows: RowGroup,
    unit: &str,
) {
    let mut f = Finding::default();
    f.key = key.to_string();
    f.label = label.to_string();
    f.category = category.to_string();
    f.explain = explain.to_string();
    let mut u = Unit::default();
    u.unit = unit.to_string();
    u.groups.push(rows);
    f.units.push(u);
    res.findings.push(f);
}
fn addf(res: &mut ScanResult, key: &str, label: &str, category: &str, explain: &str, rows: RowGroup) {
    add_finding(res, key, label, category, explain, rows, "jar");
}
fn rw(kind: &str, cls: &str, detail: &str) -> Row {
    Row {
        kind: kind.to_string(),
        detail: detail.to_string(),
        cls: cls.to_string(),
        concept: "-".to_string(),
    }
}

fn new_result(display: &str, data: &[u8], label: &str) -> ScanResult {
    let mut r = ScanResult::default();
    r.file = if label.is_empty() {
        display.to_string()
    } else {
        label.to_string()
    };
    r.name = display.to_string();
    r.sha256 = sha256_hex(data);
    r.size = data.len() as u64;
    r
}

const JAVA_KEYWORDS: &[&str] = &[
    "abstract",
    "assert",
    "boolean",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extends",
    "final",
    "finally",
    "float",
    "for",
    "goto",
    "if",
    "implements",
    "import",
    "instanceof",
    "int",
    "interface",
    "long",
    "native",
    "new",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "short",
    "static",
    "strictfp",
    "super",
    "switch",
    "synchronized",
    "this",
    "throw",
    "throws",
    "transient",
    "try",
    "void",
    "volatile",
    "while",
    "true",
    "false",
    "null",
];

fn keyword_game_client(res: &mut ScanResult, class_entries: &[(String, Bytes)]) {
    if class_entries.len() < 400 {
        return;
    }
    let game = class_entries.iter().any(|ce| {
        ce.0.starts_with("net/minecraft/client/main/Main.") || ce.0.starts_with("net/minecraft/client/Minecraft.")
    });
    if !game {
        return;
    }
    let mut kw: Vec<(String, i32)> = Vec::new(); // Counter (ekleme sıralı)
    let mut kwi: HashMap<String, usize> = HashMap::new();
    let mut hits: usize = 0;
    for ce in class_entries {
        let mut segs = split(&ce.0, "/", -1);
        segs.pop();
        let bad = segs.iter().any(|x| JAVA_KEYWORDS.contains(&x.as_str()));
        if bad {
            hits += 1;
            let pk = join(&segs, "/");
            match kwi.get(&pk) {
                None => {
                    kwi.insert(pk.clone(), kw.len());
                    kw.push((pk, 1));
                }
                Some(&i) => kw[i].1 += 1,
            }
        }
    }
    if hits < 200 || (hits as f64) < 0.25 * (class_entries.len() as f64) {
        return;
    }
    let mut mc = kw.clone();
    mc.sort_by_key(|a| std::cmp::Reverse(a.1)); // kararlı
    let mut rows: RowGroup = Vec::new();
    for m in mc.iter().take(5) {
        rows.push(rw("hint", "-", &format!("paket '{}/' : {} sınıf", m.0, m.1)));
    }
    rows.push(rw(
        "hint",
        "-",
        &format!(
            "toplam {} / {} sınıf ayrılmış-kelime paketlerinde",
            hits,
            class_entries.len()
        ),
    ));
    addf(
        res,
        "keyword_game_client",
        "Korumalı (karartılmış) değiştirilmiş Minecraft istemcisi",
        "SUPHELI",
        "Bu jar oyunun kendisini (Minecraft istemcisi) içeriyor ama sınıfların çoğu Java'nin ayrılmış \
         anahtar kelimeleriyle adlandırılmış paketlere taşınmış (or. 'case/'). Böyle paket adları Java \
         kaynak kodunda yazılamaz; yalnızca bir koruyucu/karartıcı üretir. Resmi Minecraft jar'i ve meşru \
         istemciler oyunu böyle yeniden paketlemez; özel korumalı (ücretli) hile istemcilerinin tipik \
         dağıtım biçimidir.",
        rows,
    );
}

const SRC_STRICT: &[&str] = &[
    "killaura",
    "attackaura",
    "crystalaura",
    "autocrystal",
    "anchoraura",
    "bedaura",
    "triggerbot",
    "aimassist",
    "aimbot",
    "criticals",
    "antibot",
    "antiknockback",
    "noslow",
    "noslowdown",
    "autoclicker",
    "cevbreaker",
    "autotrap",
    "elytrafly",
    "packetmine",
    "speedmine",
    "wallhack",
    "disabler",
    "selftrap",
    "holefiller",
    "autoanchor",
    "scaffoldwalk",
    "velocitybypass",
];
const SRC_CORE_EXTRA: &[&str] = &[
    "aura",
    "velocity",
    "reach",
    "fly",
    "flight",
    "speed",
    "phase",
    "spider",
    "bhop",
    "jesus",
    "longjump",
    "blink",
    "step",
    "esp",
    "tracers",
    "noclip",
    "fastplace",
    "autototem",
    "chams",
    "freecam",
    "hitboxes",
    "hitbox",
    "fullbright",
    "nofall",
    "scaffold",
    "nuker",
    "xray",
    "surround",
    "burrow",
    "timer",
    "sprint",
    "autoarmor",
    "cheststealer",
    "invmove",
];
fn src_core() -> &'static BTreeSet<&'static str> {
    static S: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    S.get_or_init(|| {
        let mut s: BTreeSet<&'static str> = SRC_STRICT.iter().copied().collect();
        s.extend(SRC_CORE_EXTRA.iter().copied());
        s
    })
}

fn src_stem(path: &str) -> String {
    let mut b = path_basename(path);
    if let Some(d) = b.rfind('.') {
        b.truncate(d);
    }
    let mut b = py_lower(&b);
    if let Some(m) = rx_stem1().search(b.as_bytes(), 0) {
        b = b.get(m.end(0)..).unwrap_or("").to_string();
    }
    let orig = b.clone();
    if let Some(m) = rx_stem2().search(b.as_bytes(), 0) {
        b = b.get(..m.start(0)).unwrap_or("").to_string();
    }
    if b.is_empty() {
        orig
    } else {
        b
    }
}

fn cheat_source(res: &mut ScanResult, sources: &[(String, Bytes)]) {
    if sources.is_empty() {
        return;
    }
    struct P<'a> {
        n: &'a str,
        b: &'a Bytes,
        pk: String,
    }
    let mut pkgs: Vec<P> = Vec::new();
    for s in sources {
        let mut pk = String::new();
        let head = &s.1[..s.1.len().min(20000)];
        if let Some(m) = rx_src_pkg().search(head, 0) {
            let mut g = String::new();
            for &c in m.group_bytes(1) {
                if c < 0x80 {
                    g.push(c as char);
                }
            }
            pk = format!("{}/", replace_all(&g, ".", "/"));
        }
        pkgs.push(P { n: &s.0, b: &s.1, pk });
    }
    let mut rows: RowGroup = Vec::new();
    let mut known: BTreeSet<String> = BTreeSet::new();
    for p in &pkgs {
        let base = path_basename(p.n);
        let cls = format!("{}{}", p.pk, base.rfind('.').map_or(base.as_str(), |d| &base[..d]));
        if !p.pk.is_empty() && starts_any(&cls, &nm().known_pfx) {
            for kc in KNOWN_CLIENTS.iter() {
                if cls.starts_with(kc.0) && !known.contains(kc.1) {
                    known.insert(kc.1.to_string());
                    rows.push(rw(
                        "ref",
                        p.n,
                        &format!("{} paketi (kaynak kod): {}", kc.1, replace_all(kc.0, "/", ".")),
                    ));
                }
            }
        }
    }
    type SrcItem<'a> = (String, &'a str, &'a str, &'a Bytes);
    let mut groups: Vec<(String, Vec<SrcItem>)> = Vec::new();
    let mut gi: HashMap<String, usize> = HashMap::new();
    for p in &pkgs {
        let st = src_stem(p.n);
        if src_core().contains(st.as_str()) && !p.pk.is_empty() {
            let segs = split(&p.pk, "/", -1);
            let root = join(&segs[..segs.len().min(2)], "/");
            let idx = match gi.get(&root) {
                Some(&i) => i,
                None => {
                    gi.insert(root.clone(), groups.len());
                    groups.push((root.clone(), Vec::new()));
                    groups.len() - 1
                }
            };
            groups[idx].1.push((st, p.n, p.pk.as_str(), p.b));
        }
    }
    for g in &groups {
        let mut stems: BTreeSet<&str> = BTreeSet::new();
        let mut strict: BTreeSet<&str> = BTreeSet::new();
        let mut mc = false;
        for x in &g.1 {
            stems.insert(x.0.as_str());
            if SRC_STRICT.contains(&x.0.as_str()) {
                strict.insert(x.0.as_str());
            }
            if bcontains(x.3, b"net.minecraft") || bcontains(x.3, b"net/minecraft") {
                mc = true;
            }
        }
        if strict.len() >= 2 && stems.len() >= 4 && mc {
            let mut lst: Vec<&SrcItem> = g.1.iter().collect();
            lst.sort_by(|a, b| {
                let as_ = !SRC_STRICT.contains(&a.0.as_str());
                let bs = !SRC_STRICT.contains(&b.0.as_str());
                if as_ != bs {
                    return as_.cmp(&bs);
                }
                a.0.cmp(&b.0)
            });
            for it in lst.iter().take(8) {
                rows.push(rw(
                    "hint",
                    it.1,
                    &format!(
                        "hile modülü kaynak kodu: {} (paket {})",
                        it.0,
                        replace_all(&rstrip(it.2, "/"), "/", ".")
                    ),
                ));
            }
            known.insert(format!("modül ağacı: {}", replace_all(&g.0, "/", ".")));
            break;
        }
    }
    if !rows.is_empty() {
        let ks: StrList = known.iter().cloned().collect();
        rows.truncate(12);
        addf(
            res,
            "cheat_source",
            "Hile istemcisi KAYNAK KODU",
            "KESIN_HILE",
            &format!(
                "Arşivde bir hile istemcisinin Java/Kotlin kaynak kodu var ({}). Kaynak koddaki paket bildirimleri ve modül sınıfları (KillAura, TriggerBot, Velocity ...) \
                 Minecraft koduna erişen bir hile istemcisine ait; derlenip oyuna eklenmeye hazır haldedir.",
                join(&ks, ", ")
            ),
            rows,
        );
    }
}

const CL_SUPERS: &[&str] = &[
    "java/lang/ClassLoader",
    "java/security/SecureClassLoader",
    "java/net/URLClassLoader",
];
const MEM_ARCHIVE: &[&str] = &["java/util/jar/JarInputStream", "java/util/zip/ZipInputStream"];
fn token_ref(o: &str, n: &str) -> bool {
    const T: &[(&str, &str)] = &[
        ("net/minecraft/class_320", "method_1674"),
        ("net/minecraft/client/User", "getAccessToken"),
        ("net/minecraft/client/session/Session", "getAccessToken"),
        ("net/minecraft/client/util/Session", "getAccessToken"),
        ("net/minecraft/util/Session", "getToken"),
        ("net/minecraft/util/Session", "func_148254_d"),
        ("net/minecraft/client/User", "func_148254_d"),
    ];
    T.iter().any(|t| t.0 == o && t.1 == n)
}
const LIB_PREFIXES: &[&str] = &[
    "org/",
    "com/google/",
    "com/sun/",
    "io/",
    "it/unimi/",
    "kotlin/",
    "javax/",
    "net/java/",
    "com/fasterxml/",
    "okhttp3/",
    "okio/",
    "org/lwjgl/",
    "net/minecraft/",
    "com/mojang/",
];

fn junk_name(s: &str) -> bool {
    let b = s.as_bytes();
    let n = b.len();
    let mut i = 0usize;
    while i < n && b"IlOo0ij1_$".contains(&b[i]) && b[i] != 0 {
        i += 1;
    }
    if i < 2 {
        return false;
    }
    let mut j = i;
    while j < n && b[j].is_ascii_digit() {
        j += 1;
    }
    j == n
}

fn junk_ratio(evs: &[&ClassEv]) -> f64 {
    let mut tot = 0i32;
    let mut junk = 0i32;
    for e in evs {
        for b in &e.bodies {
            let nm = b.name.as_str();
            if nm == "<init>"
                || nm == "<clinit>"
                || nm.starts_with("lambda$")
                || nm.starts_with("access$")
                || nm.starts_with("$values")
                || nm.starts_with("$jnic")
            {
                continue;
            }
            tot += 1;
            if (nm.contains('$') && !nm.starts_with('$')) || junk_name(nm) || nm.starts_with('$') {
                junk += 1;
            }
        }
    }
    if tot >= 10 {
        junk as f64 / tot as f64
    } else {
        0.0
    }
}

fn memory_loader(res: &mut ScanResult, evs: &[&ClassEv], is_mod: bool, obf_hint: bool) {
    if !is_mod {
        return;
    }
    let mut loaders: Vec<(String, String)> = Vec::new();
    let mut archives: Vec<(String, String)> = Vec::new();
    let mut tokens: Vec<(String, String)> = Vec::new();
    for e in evs {
        let own_cl = in_list(&e.super_, CL_SUPERS);
        for c in &e.calls {
            let o = c.owner.as_str();
            let n = c.name.as_str();
            if (n == "defineClass" || n == "defineClass0" || n == "defineClass1")
                && (own_cl || in_list(o, CL_SUPERS) || o == e.name)
            {
                loaders.push((e.name.clone(), format!("{}.{}", last_seg(o, "/"), n)));
            } else if in_list(o, MEM_ARCHIVE) && n == "<init>" {
                let bais = e
                    .calls
                    .iter()
                    .any(|c2| c2.owner == "java/io/ByteArrayInputStream" && c2.name == "<init>");
                if bais {
                    archives.push((
                        e.name.clone(),
                        format!("{}(new ByteArrayInputStream(...))", last_seg(o, "/")),
                    ));
                } else if token_ref(o, n) || n == "func_148254_d" {
                    tokens.push((
                        e.name.clone(),
                        format!("{}.{} (oturum erişim anahtarı)", last_seg(o, "/"), n),
                    ));
                }
            } else if token_ref(o, n) || n == "func_148254_d" {
                tokens.push((
                    e.name.clone(),
                    format!("{}.{} (oturum erişim anahtarı)", last_seg(o, "/"), n),
                ));
            }
        }
    }
    if loaders.is_empty() || archives.is_empty() {
        return;
    }
    let junk = junk_ratio(evs);
    if !(!tokens.is_empty() || obf_hint || junk >= 0.25) {
        return;
    }
    let mut why: StrList = vec![
        format!("mod kendi içindeki gizli bir JAR'i bellekte açıyor ({})", archives[0].1),
        format!(
            "özel bir sınıf yükleyiciyle bu kodu tanımlayıp çalıştırıyor ({})",
            loaders[0].1
        ),
    ];
    if !tokens.is_empty() {
        why.push("Minecraft hesabının OTURUM ERİŞİM ANAHTARINI okuyor (hesap çalma riski)".to_string());
    }
    if junk >= 0.25 {
        why.push(format!(
            "kod adları karartılmış (%{} anlamsız metot adı)",
            (junk * 100.0) as i32
        ));
    }
    let mut rows: RowGroup = Vec::new();
    for a in archives.iter().take(2) {
        rows.push(rw("call", &a.0, &a.1));
    }
    for a in loaders.iter().take(2) {
        rows.push(rw("call", &a.0, &a.1));
    }
    for a in tokens.iter().take(2) {
        rows.push(rw("call", &a.0, &a.1));
    }
    addf(
        res,
        "memory_loader",
        "Gizli kodu bellekte çalıştıran sahte mod (ghost loader)",
        "KESIN_HILE",
        &format!(
            "Bu mod gerçek işlevini gizliyor: {}. Bu yapı, meşru bir modun adına/kimliğine bürünerek gizli hile (ve çoğu zaman hesap çalıcı) \
             kodu oyuna sokan yükleyicilere özgüdür. Dosyayı ÇALIŞTIRMAYIN; hesap şifrenizi ve oturumlarinizi \
             yenileyin.",
            join(&why, "; ")
        ),
        rows,
    );
}

fn native_module_client(res: &mut ScanResult, evs: &[&ClassEv], is_mod: bool) {
    if !is_mod {
        return;
    }
    let own: Vec<&ClassEv> = evs
        .iter()
        .copied()
        .filter(|e| !starts_any(&e.name, LIB_PREFIXES))
        .collect();
    let names: HashSet<&str> = own.iter().map(|e| e.name.as_str()).collect();
    let mut jnic = false;
    for e in &own {
        for b in &e.bodies {
            if b.name.starts_with("$jnic") {
                jnic = true;
            }
        }
    }
    for e in evs {
        if e.name.starts_with("dev/jnic/") {
            jnic = true;
        }
    }
    if !jnic {
        return;
    }
    let mut subs: Vec<(String, Vec<&ClassEv>)> = Vec::new();
    let mut si: HashMap<String, usize> = HashMap::new();
    for e in &own {
        if names.contains(e.super_.as_str()) {
            let idx = match si.get(&e.super_) {
                Some(&i) => i,
                None => {
                    si.insert(e.super_.clone(), subs.len());
                    subs.push((e.super_.clone(), Vec::new()));
                    subs.len() - 1
                }
            };
            subs[idx].1.push(e);
        }
    }
    let mut best: Option<usize> = None;
    let mut best_nat: Vec<&ClassEv> = Vec::new();
    for (si_, s) in subs.iter().enumerate() {
        let mut nat: Vec<&ClassEv> = Vec::new();
        for x in &s.1 {
            let nt = x.bodies.iter().any(|b| b.access & 0x100 != 0);
            if nt {
                nat.push(x);
            }
        }
        if nat.len() >= 10
            && (nat.len() as f64) >= 0.5 * (s.1.len() as f64)
            && (best.is_none() || nat.len() > best_nat.len())
        {
            best = Some(si_);
            best_nat = nat;
        }
    }
    let Some(best) = best else { return };
    let best = &subs[best];
    let mut rows: RowGroup = vec![rw("ref", &best.0, &format!("taban sınıf ({} alt sınıf)", best.1.len()))];
    for n in best_nat.iter().take(5) {
        rows.push(rw("ref", &n.name, "native (yerel) metotlu modül sınıfı"));
    }
    addf(
        res,
        "native_module_client",
        "Kodu yerel koda (JNIC) gizlenmiş modül tabanlı istemci",
        "KESIN_HILE",
        &format!(
            "Mod, ortak bir taban sınıftan ({}) türemiş {} 'özellik/modül' sınıfı içeriyor ve bunların {} \
             tanesinin kodu JNIC ile yerel (DLL) koda çevrilip gizlenmiş. Gerçek işlevini saklayan modül \
             tabanlı hile istemcilerinin (örnek: Grim) dağıtım biçimidir; meşru modlar oyun kodunu böyle \
             gizlemez.",
            dotted(&best.0),
            best.1.len(),
            best_nat.len()
        ),
        rows,
    );
}

fn handle_closer(res: &mut ScanResult, class_entries: &[(String, Bytes)], game_ctx: bool) {
    const W: [&str; 4] = [
        "NtQuerySystemInformation",
        "NtQueryObject",
        "DuplicateHandle",
        "OpenProcess",
    ];
    let mut hits: StrList = Vec::new();
    for ce in class_entries {
        if ce.0.starts_with("com/sun/jna/") {
            continue;
        }
        if W.iter().all(|w| bcontains(&ce.1, w.as_bytes())) {
            hits.push(ce.0.clone());
        }
    }
    if hits.is_empty() {
        return;
    }
    let mut rows: RowGroup = Vec::new();
    for h in hits.iter().take(4) {
        rows.push(rw("ref", h, "tutamaç kapatma kodu"));
    }
    addf(
        res,
        "handle_closer",
        "Kendini silme / iz gizleme aracı (başka sürecin dosya tutamaçlarını kapatır)",
        if game_ctx { "KESIN_HILE" } else { "SUPHELI" },
        "Kod, sistemdeki tüm açık tutamaçları listeleyip (NtQuerySystemInformation), adlarını okuyup \
         (NtQueryObject) başka bir sürecin (Minecraft/javaw) dosya tutamacını kapatıyor (DuplicateHandle). \
         Böylece kullanılan hile dosyası oyun açıkken silinebilir - ekran paylaşımı/kontrol öncesi iz silme \
         (self-destruct) yöntemidir.",
        rows,
    );
}

const DEFINE_OWNERS: &[&str] = &[
    "java/lang/ClassLoader",
    "java/security/SecureClassLoader",
    "java/lang/invoke/MethodHandles$Lookup",
    "sun/misc/Unsafe",
    "jdk/internal/misc/Unsafe",
    "java/lang/reflect/Proxy",
];
const NET_OWNERS: &[&str] = &[
    "java/net/URL",
    "java/net/HttpURLConnection",
    "java/net/URLConnection",
    "java/net/http/HttpClient",
    "java/net/Socket",
    "javax/net/ssl/HttpsURLConnection",
    "java/net/http/HttpRequest",
    "okhttp3/",
    "org/apache/http/",
    "java/nio/channels/SocketChannel",
    "java/nio/channels/DatagramChannel",
    "java/nio/channels/AsynchronousSocketChannel",
    "java/net/DatagramSocket",
];
const INSTR_NAMES: &[&str] = &[
    "redefineClasses",
    "retransformClasses",
    "addTransformer",
    "appendToSystemClassLoaderSearch",
    "appendToBootstrapClassLoaderSearch",
    "redefineModule",
];

#[derive(Debug, Clone, Default)]
struct AgentMatch {
    ok: bool,
    kind: String,
    cls: String,
}

const QP_LIB_TAILS: &[&str] = &["org/objectweb/asm/", "com/google/gson/", "com/google/errorprone/"];
fn qp_is_relocated_lib(n: &str) -> bool {
    for mark in ["/shadow/", "/shaded/", "/relocated/", "/libs/", "/lib/"] {
        let Some(p) = n.find(mark) else { continue };
        let tail = &n[p + mark.len()..];
        if starts_any(tail, QP_LIB_TAILS) {
            return true;
        }
    }
    starts_any(n, QP_LIB_TAILS)
}
fn qp_class_like(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 6 || !s.contains('/') || s.contains(' ') {
        return false;
    }
    if b[0] == b'(' || b[0] == b'L' || b[0] == b'[' {
        return false; // tanımlayıcı (descriptor)
    }
    b.iter()
        .all(|&c| c.is_ascii_alphanumeric() || c == b'/' || c == b'_' || c == b'$')
}

fn verify_quickplay_launcher_agent(
    evs: &[&ClassEv],
    agent: &AgentMatch,
    obf_ratio: f64,
    hidden_classes: &[String],
    mut why_not: Option<&mut String>,
) -> bool {
    let mut no = |w: &str| -> bool {
        if let Some(r) = why_not.as_deref_mut() {
            *r = w.to_string();
        }
        false
    };
    if !agent.ok || agent.kind != "Premain-Class" {
        return no("Premain-Class ajanı değil");
    }
    if obf_ratio >= 0.3 || !hidden_classes.is_empty() {
        return no("karartılmış / gizli sınıf");
    }
    let acls = replace_all(&agent.cls, ".", "/");
    let mut own: Vec<&ClassEv> = Vec::new();
    let mut agent_found = false;
    for e in evs {
        if qp_is_relocated_lib(&e.name) {
            continue;
        }
        own.push(e);
        if e.name == acls {
            agent_found = true;
        }
    }
    if !agent_found {
        return no("ajan sınıfı arşivde yok");
    }
    if own.is_empty() || own.len() > 40 {
        return no("kendi kodu çok büyük");
    }
    const ALLOWED_CLASS_CONSTS: [&str; 4] = [
        "net/minecraft/client/Minecraft",
        "java/lang/System",
        "java/lang/Integer",
        "java/lang/String",
    ];
    let mut targets_mc = false;
    let mut add_transformer = 0;
    let acls_dir: &str = match acls.rfind('/') {
        Some(i) => &acls[..i + 1],
        None => "",
    };
    for e in &own {
        if e.indy_custom > 0 {
            return no("gizlenmiş çağrı referansı");
        }
        for r in &e.refs {
            if r.starts_with("net/minecraft/") || r.starts_with("com/mojang/") || r.starts_with("org/lwjgl/") {
                return no(&format!("oyun sınıfına doğrudan referans: {}", r));
            }
        }
        for st in &e.strings {
            let l = py_lower(st);
            if l.contains("net/minecraft/")
                || l.contains("net.minecraft.")
                || l.contains("class_")
                || l.contains("com/mojang/")
            {
                if st != "net/minecraft/client/Minecraft" {
                    return no(&format!("başka oyun sınıfı hedefi: {}", st));
                }
                targets_mc = true;
                continue;
            }
            if qp_class_like(st)
                && !ALLOWED_CLASS_CONSTS.contains(&st.as_str())
                && !st.starts_with(acls_dir)
                && (st.starts_with("java/")
                    || st.starts_with("sun/")
                    || st.starts_with("jdk/")
                    || st.starts_with("javax/"))
            {
                return no(&format!("enjekte edilen kodda izin dışı sınıf: {}", st));
            }
        }
        for c in &e.calls {
            let o = c.owner.as_str();
            let n = c.name.as_str();
            if o == "java/lang/instrument/Instrumentation" {
                if n == "addTransformer" {
                    add_transformer += 1;
                    continue;
                }
                if n == "isRetransformClassesSupported"
                    || n == "isRedefineClassesSupported"
                    || n == "getAllLoadedClasses"
                {
                    continue;
                }
                return no(&format!("Instrumentation.{}", n));
            }
            if o.starts_with("com/sun/tools/attach/") || o.starts_with("net/bytebuddy/agent/") {
                return no("Attach API");
            }
            if n == "defineClass" || n == "defineHiddenClass" || n == "defineAnonymousClass" {
                return no("defineClass");
            }
            if o.starts_with("sun/misc/Unsafe") || o.starts_with("jdk/internal/misc/Unsafe") {
                return no("Unsafe");
            }
            if o == "javax/crypto/Cipher" {
                return no("şifre çözme");
            }
            if (o == "java/lang/Runtime" && (n == "exec" || n == "load" || n == "loadLibrary"))
                || o == "java/lang/ProcessBuilder"
                || (o == "java/lang/System" && (n == "load" || n == "loadLibrary"))
            {
                return no("komut / yerel kütüphane");
            }
            if o.starts_with("com/sun/jna/") {
                return no("JNA");
            }
            if starts_any(o, NET_OWNERS) && o != "java/net/Socket" {
                return no(&format!("ağ indirme: {}", o));
            }
            if o == "java/net/URLClassLoader" || (n == "<init>" && o.contains("ClassLoader")) {
                return no("sınıf yükleyici");
            }
        }
    }
    if !targets_mc {
        return no("Minecraft istemci sınıfı hedeflenmiyor");
    }
    if add_transformer == 0 {
        return no("transformer eklemiyor");
    }
    true
}

type RL = Vec<(String, String)>;
fn loader_rows(l: &[(String, String)], lim: usize, kind: &str) -> RowGroup {
    let mut g = Vec::new();
    for x in l.iter().take(lim) {
        g.push(rw(kind, &x.0, &x.1));
    }
    g
}
fn cat_rows(mut a: RowGroup, b: RowGroup) -> RowGroup {
    a.extend(b);
    a
}

fn loader_checks(
    res: &mut ScanResult,
    evs: &[&ClassEv],
    agent: &AgentMatch,
    raw_mc: bool,
    mentions_game: bool,
    obf_ratio: f64,
    hidden_classes: &[String],
    nested_pe: &[(String, Bytes)],
    is_mod: bool,
    trusted_infra: bool,
    opaque_bytes: u64,
    opaque_names: &[String],
) {
    let agent_name = if agent.ok {
        replace_all(&agent.cls, ".", "/")
    } else {
        String::new()
    };
    let mut legit = trusted_infra;
    for p in LEGIT_AGENT_PKGS {
        if agent_name.starts_with(p) {
            legit = true;
            break;
        }
        for e in evs.iter().take(200) {
            if e.name.starts_with(p) {
                legit = true;
                break;
            }
        }
        if legit {
            break;
        }
    }
    if !legit {
        let an = replace_all(&py_lower(&agent_name), "/", "");
        for h in LEGIT_AGENT_HINTS.iter() {
            let hh = replace_all(&replace_all(h, "-", ""), "_", "");
            if an.contains(&hh) {
                legit = true;
                break;
            }
        }
    }
    let mut rows_attach: RL = Vec::new();
    let mut rows_instr: RL = Vec::new();
    let mut rows_def: RL = Vec::new();
    let mut rows_net: RL = Vec::new();
    let mut rows_cip: RL = Vec::new();
    let mut rows_res: RL = Vec::new();
    let mut rows_jna: RL = Vec::new();
    for e in evs {
        for c in &e.calls {
            let o = c.owner.as_str();
            let n = c.name.as_str();
            if (n == "getResourceAsStream" || n == "getResource")
                && (o == "java/lang/Class" || o == "java/lang/ClassLoader" || o == "java/lang/Module")
            {
                rows_res.push((e.name.clone(), format!("{}.{}", last_seg(o, "/"), n)));
            } else if o.starts_with("com/sun/jna/")
                && (n == "invokePointer"
                    || n == "invoke"
                    || n == "invokeInt"
                    || n == "invokeLong"
                    || n == "invokeVoid"
                    || n == "getFunction")
            {
                rows_jna.push((e.name.clone(), format!("{}.{}", last_seg(o, "/"), n)));
            }
            if (o.starts_with("com/sun/tools/attach/")
                && (n == "attach" || n == "loadAgent" || n == "loadAgentPath" || n == "loadAgentLibrary"))
                || (o.starts_with("net/bytebuddy/agent/") && (n == "install" || n == "attach"))
            {
                rows_attach.push((e.name.clone(), format!("{}.{}", last_seg(o, "/"), n)));
            } else if o == "java/lang/instrument/Instrumentation" && in_list(n, INSTR_NAMES) {
                rows_instr.push((e.name.clone(), format!("Instrumentation.{}", n)));
            } else if (n == "defineClass"
                || n == "defineHiddenClass"
                || n == "defineAnonymousClass"
                || n == "defineClass0"
                || n == "defineClass1")
                && (starts_any(o, DEFINE_OWNERS) || !o.starts_with("java/") || o == e.name)
            {
                let who = if starts_any(o, DEFINE_OWNERS) {
                    last_seg(o, "/")
                } else {
                    dotted(o)
                };
                rows_def.push((e.name.clone(), format!("{}.{}", who, n)));
            } else if starts_any(o, NET_OWNERS)
                && (n == "openStream"
                    || n == "openConnection"
                    || n == "send"
                    || n == "sendAsync"
                    || n == "<init>"
                    || n == "getInputStream"
                    || n == "execute"
                    || n == "newCall")
            {
                rows_net.push((e.name.clone(), format!("{}.{}", last_seg(o, "/"), n)));
            } else if o == "javax/crypto/Cipher" && (n == "getInstance" || n == "doFinal" || n == "init") {
                rows_cip.push((e.name.clone(), format!("Cipher.{}", n)));
            }
        }
        let sl: HashSet<&str> = e.strings.iter().map(|s| s.as_str()).collect();
        if sl.contains("com.sun.tools.attach.VirtualMachine") && (sl.contains("loadAgent") || sl.contains("attach")) {
            rows_attach.push((
                e.name.clone(),
                "yansıma ile VirtualMachine.attach/loadAgent".to_string(),
            ));
        }
    }
    let has_attach = rows_attach
        .iter()
        .any(|r| r.1.contains("loadAgent") || r.1.contains("install") || r.1.contains("yansıma"));
    let game = raw_mc || mentions_game;
    let mut indy_obf = 0i32;
    for e in evs {
        indy_obf += e.indy_custom;
    }
    let obf = obf_ratio >= 0.6 || indy_obf >= 5;
    let mut why: StrList = Vec::new();
    if game {
        why.push("Minecraft / javaw / LWJGL hedefliyor".to_string());
    }
    if obf {
        why.push(format!(
            "kodu karartılmış{}",
            if obf_ratio >= 0.6 {
                format!(" (%{} kısa sınıf adı)", (obf_ratio * 100.0) as i32)
            } else {
                " (gizlenmiş çağrı referansları)".to_string()
            }
        ));
    }
    if !rows_net.is_empty() {
        why.push(format!("internetten veri/kod indiriyor ({})", rows_net[0].1));
    }
    if !rows_cip.is_empty() {
        why.push(format!("şifreli içerik çözüyor ({})", rows_cip[0].1));
    }
    if !rows_def.is_empty() {
        why.push(format!("bellekte sınıf tanımlıyor ({})", rows_def[0].1));
    }
    if !hidden_classes.is_empty() {
        why.push("uzantısı gizlenmiş sınıf dosyaları var".to_string());
    }
    let rows = |l: &RL| loader_rows(l, 4, "call");
    let rows_n = |l: &RL, n: usize| loader_rows(l, n, "call");
    let whys = if why.is_empty() {
        "-".to_string()
    } else {
        join(&why, ", ")
    };
    if has_attach
        && !legit
        && (game || obf || (agent.ok && (!rows_net.is_empty() || !rows_cip.is_empty() || !rows_def.is_empty())))
    {
        let i2: RL = rows_instr.iter().take(2).cloned().collect();
        let n1: RL = rows_net.iter().take(1).cloned().collect();
        let c1: RL = rows_cip.iter().take(1).cloned().collect();
        addf(
            res,
            "injector",
            "Çalışan oyuna kod enjekte eden yükleyici (injector / ghost client loader)",
            "KESIN_HILE",
            &format!(
                "Bu JAR çalışan bir Java sürecine (Minecraft) bağlanıp (Attach API) ona kendi kodunu agent olarak \
                 yüklüyor: {}. Ghost client'larin mod klasörü OLMADAN oyuna girme yöntemidir; dosya adı / uzantısı ne \
                 olursa olsun (.txt, .png, uzantısız ...) içerik olarak tespit edilir.",
                whys
            ),
            cat_rows(cat_rows(cat_rows(rows(&rows_attach), rows(&i2)), rows(&n1)), rows(&c1)),
        );
        return;
    }
    if agent.ok
        && !rows_instr.is_empty()
        && !legit
        && (raw_mc || mentions_game || (obf && (!rows_net.is_empty() || !rows_cip.is_empty())))
    {
        addf(
            res,
            "java_agent",
            "Minecraft'in kodunu değiştiren Java agent",
            "KESIN_HILE",
            &format!(
                "JAR bir Java agent ({}: {}) ve Instrumentation ile çalışan oyunun sınıflarını değiştiriyor: {}. \
                 Mod klasörü kontrolünü atlatarak oyuna kod sokmak için kullanılır.",
                agent.kind, agent.cls, whys
            ),
            cat_rows(vec![rw("ref", &agent_name, "agent sınıfı")], rows(&rows_instr)),
        );
        return;
    }
    let dyn_agent = agent.ok && (agent.kind == "Agent-Class" || agent.kind == "Launcher-Agent-Class");
    if dyn_agent && obf && (!rows_net.is_empty() || !rows_cip.is_empty() || !rows_def.is_empty()) && !legit {
        addf(
            res,
            "java_agent",
            "Çalışan oyuna sonradan yüklenen gizli Java agent (ghost client)",
            "KESIN_HILE",
            &format!(
                "JAR, çalışan bir Java sürecine sonradan yüklenmek için hazırlanmış bir agent ({}: {}) ve: {}. \
                 Karartılmış + şifreli/indirilen kod çalıştıran bu yapı ghost client yükleyicilerine özgüdür.",
                agent.kind,
                agent.cls,
                join(&why, ", ")
            ),
            cat_rows(
                cat_rows(
                    cat_rows(vec![rw("ref", &agent_name, "agent sınıfı")], rows_n(&rows_net, 2)),
                    rows_n(&rows_cip, 2),
                ),
                rows_n(&rows_def, 2),
            ),
        );
        return;
    }
    if !legit && !rows_def.is_empty() && !rows_res.is_empty() && opaque_bytes >= (64u64 << 10) {
        let mut ev2: StrList = Vec::new();
        ev2.push(format!(
            "şifreli gömülü yük: {:.1} MB ({} dosya)",
            opaque_bytes as f64 / 1048576.0,
            opaque_names.len()
        ));
        for n in opaque_names.iter().take(6) {
            ev2.push(n.clone());
        }
        let mut g: RowGroup = Vec::new();
        for x in &ev2 {
            g.push(rw("hint", "-", x));
        }
        for r in rows_res.iter().take(2) {
            g.push(rw("call", &r.0, &r.1));
        }
        for r in rows_def.iter().take(2) {
            g.push(rw("call", &r.0, &r.1));
        }
        for r in rows_jna.iter().take(2) {
            g.push(rw("call", &r.0, &r.1));
        }
        if agent.ok {
            g.push(rw("ref", &agent_name, &format!("agent sınıfı ({})", agent.kind)));
        }
        let mut expl = format!(
            "Arşivde bilinen hiçbir biçime uymayan, neredeyse tamamen rastgele (şifreli) {:.1} MB veri var; \
             mod bu veriyi kendi arşivinden okuyup (getResourceAsStream) bellekte sınıf olarak tanımlayıp \
             çalıştırıyor (defineClass). Gerçek kod diskte hiçbir zaman görünmez - ghost client'larin \
             tarayıcılardan kaçmak için kullandığı paketleme yöntemidir.",
            opaque_bytes as f64 / 1048576.0
        );
        if agent.ok {
            expl.push_str(&format!(
                "  Ayrıca bir Java agent ({}: {}) olarak çalışan oyuna bağlanabiliyor.",
                agent.kind, agent.cls
            ));
        }
        if !rows_jna.is_empty() {
            expl.push_str(
                "  JNA ile doğrudan yerel (native) fonksiyon çağırıyor: diskte DLL \
                 bırakmadan yerel kod çalıştırabilir.",
            );
        }
        if !why.is_empty() {
            expl.push_str(&format!("  Ek: {}.", join(&why, ", ")));
        }
        addf(
            res,
            "packed_loader",
            "Şifreli gömülü kodu bellekte çalıştıran paketlenmiş yükleyici",
            "KESIN_HILE",
            &expl,
            g,
        );
        return;
    }
    if is_mod && !rows_def.is_empty() && (!rows_cip.is_empty() || !rows_net.is_empty()) && obf && !legit {
        addf(
            res,
            "hidden_loader",
            "Gizli kodu bellekte çalıştıran mod (şifreli / indirilen kod)",
            "KESIN_HILE",
            &format!(
                "Mod, karartılmış kodunda şifreli ya da internetten indirdiği sınıf baytlarını bellekte tanımlayıp \
                 çalıştırıyor: {}. Gerçek işlevini gizleyen ghost client yöntemidir.",
                join(&why, ", ")
            ),
            cat_rows(cat_rows(rows(&rows_def), rows_n(&rows_cip, 2)), rows_n(&rows_net, 2)),
        );
        return;
    }
    for np in nested_pe {
        let mut ex = String::new();
        let mut evd: StrList = Vec::new();
        if pe_injector_check(&np.1, &mut ex, &mut evd) {
            let mut g: RowGroup = Vec::new();
            for e in evd.iter().take(6) {
                g.push(rw("hint", "-", e));
            }
            addf(
                res,
                "native_injector",
                "İçinde Java'ya (Minecraft) kod enjekte eden yerel program var",
                "KESIN_HILE",
                &format!("Arşivin içindeki '{}' dosyası: {}", np.0, ex),
                g,
            );
            return;
        }
    }
}

fn words_of(text: &str) -> StrList {
    let mut out: StrList = Vec::new();
    let t = text.as_bytes();
    let n = t.len();
    let mut i = 0usize;
    let isal = |c: u8| c < 0x80 && c.is_ascii_alphanumeric();
    let sub = |a: usize, b: usize| -> &str { text.get(a..b).unwrap_or("") };
    while i < n {
        while i < n && !isal(t[i]) {
            i += 1;
        }
        let mut j = i;
        while j < n && isal(t[j]) {
            j += 1;
        }
        let mut p = i;
        while p < j {
            let c = t[p];
            if c.is_ascii_uppercase() && p + 1 < j && t[p + 1].is_ascii_lowercase() {
                let mut q = p + 1;
                while q < j && t[q].is_ascii_lowercase() {
                    q += 1;
                }
                out.push(lower_ascii(sub(p, q)));
                p = q;
            } else if c.is_ascii_lowercase() {
                let mut q = p;
                while q < j && t[q].is_ascii_lowercase() {
                    q += 1;
                }
                out.push(sub(p, q).to_string());
                p = q;
            } else if c.is_ascii_uppercase() {
                let mut q = p;
                while q < j && t[q].is_ascii_uppercase() {
                    q += 1;
                }
                if q < j && t[q].is_ascii_lowercase() {
                    q -= 1;
                }
                if q == p {
                    q = p + 1; // tek büyük harf + küçük: üst dalda işlenir (buraya düşmez)
                }
                out.push(lower_ascii(sub(p, q)));
                p = q;
            } else if c.is_ascii_digit() {
                let mut q = p;
                while q < j && t[q].is_ascii_digit() {
                    q += 1;
                }
                out.push(sub(p, q).to_string());
                p = q;
            } else {
                p += 1;
            }
        }
        i = j;
    }
    out
}

fn has_term(words: &[String], term: &str) -> bool {
    let n = words.len();
    for i in 0..n {
        let mut acc = String::new();
        for w in words.iter().take(n.min(i + 4)).skip(i) {
            acc.push_str(w);
            if acc == term {
                return true;
            }
            if acc.len() >= term.len() {
                break;
            }
        }
    }
    false
}

fn touches_mc(e: &ClassEv) -> bool {
    e.refs
        .iter()
        .any(|r| r.starts_with("net/minecraft/") || r.starts_with("com/mojang/blaze3d/"))
}

fn cheat_terms(res: &mut ScanResult, evs_in: &[&ClassEv]) {
    let evs: Vec<&ClassEv> = evs_in.iter().copied().filter(|e| touches_mc(e)).collect();
    struct Hit3 {
        term: String,
        cls: String,
        where_: &'static str,
    }
    let mut hits: Vec<Hit3> = Vec::new();
    let terms: StrList = STRONG_CHEAT_TERMS.iter().map(|s| s.to_string()).collect(); // sıralı
    for e in &evs {
        let idw: Vec<StrList> = e.idents.iter().map(|x| words_of(x)).collect();
        let mut stw: Vec<StrList> = Vec::new();
        for x in &e.strings {
            if !x.is_empty() && ulen(x) <= 200 {
                stw.push(words_of(x));
            }
        }
        for t in &terms {
            let mut where_: Option<&'static str> = None;
            for w in &idw {
                if has_term(w, t) {
                    where_ = Some("sınıf/metot/alan adı");
                    break;
                }
            }
            if where_.is_none() {
                for w in &stw {
                    if has_term(w, t) {
                        where_ = Some("kod içindeki metin");
                        break;
                    }
                }
            }
            if let Some(w) = where_ {
                hits.push(Hit3 {
                    term: t.clone(),
                    cls: e.name.clone(),
                    where_: w,
                });
            }
        }
    }
    if hits.is_empty() {
        return;
    }
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut rows: RowGroup = Vec::new();
    for h in &hits {
        if !seen.insert((h.term.clone(), h.cls.clone())) {
            continue;
        }
        rows.push(rw("hint", &h.cls, &format!("'{}' ({})", h.term, h.where_)));
    }
    rows.truncate(12);
    addf(
        res,
        "cheat_terms",
        "Hile terimleri",
        "KESIN_HILE",
        "Minecraft koduna dokunan sınıflarda hile modüllerinin TAM adları bulundu.",
        rows,
    );
}

fn mcp_combat(evs: &[&ClassEv]) -> Option<Hit> {
    const OWN: &[&str] = &[
        "net/minecraft/client/multiplayer/PlayerController",
        "net/minecraft/client/multiplayer/PlayerControllerMP",
    ];
    const NMS: &[&str] = &["attackEntity", "func_78764_a"];
    const PKT: &[&str] = &[
        "net/minecraft/network/play/client/CUseEntityPacket",
        "net/minecraft/network/play/client/CPacketUseEntity",
        "net/minecraft/network/play/client/C02PacketUseEntity",
    ];
    for e in evs {
        for c in &e.calls {
            if in_list(&c.owner, OWN) && in_list(&c.name, NMS) {
                return hit(
                    "call",
                    format!(
                        "{}.{} (oyuncu adına varlığa vurma - MCP)",
                        last_seg(&c.owner, "/"),
                        c.name
                    ),
                );
            }
        }
        for r in &e.refs {
            if in_list(r, PKT) {
                return hit("ref", format!("{} (varlığa vurma paketi - MCP)", last_seg(r, "/")));
            }
        }
    }
    None
}

fn client_layout(res: &mut ScanResult, evs: &[&ClassEv], game_jar: bool) {
    if res.official_fabric || evs.len() < 10 {
        return;
    }
    let mut cats: BTreeSet<&str> = BTreeSet::new();
    let catset: HashSet<&str> = CLIENT_CATEGORY_STRINGS.iter().copied().collect();
    for e in evs {
        for s in &e.strings {
            if let Some(c) = catset.get(s.as_str()) {
                cats.insert(c);
            }
        }
    }
    if cats.len() < 5 {
        return;
    }
    let mut supers: Vec<(String, StrList)> = Vec::new();
    let mut si: HashMap<String, usize> = HashMap::new();
    for e in evs {
        if !e.super_.is_empty()
            && !e.super_.starts_with("java/")
            && !e.super_.starts_with("net/minecraft/")
            && !e.super_.starts_with("com/mojang/")
        {
            let idx = match si.get(&e.super_) {
                Some(&i) => i,
                None => {
                    si.insert(e.super_.clone(), supers.len());
                    supers.push((e.super_.clone(), Vec::new()));
                    supers.len() - 1
                }
            };
            supers[idx].1.push(e.name.clone());
        }
    }
    let mut base = String::new();
    let mut subs: StrList = Vec::new();
    for s in &supers {
        let tail = py_lower(&last_seg(&s.0, "/"));
        if (tail.contains("module")
            || tail.contains("hack")
            || tail.contains("feature")
            || tail.contains("cheat")
            || tail == "function")
            && s.1.len() > subs.len()
        {
            base = s.0.clone();
            subs = s.1.clone();
        }
    }
    if subs.len() < 8 {
        return;
    }
    let ctx = Ctx::new(evs);
    let mut combat: Option<Hit> = None;
    let probes: [(&str, &[&str]); 4] = [
        ("M_ATTACK_ENTITY", &["call"]),
        ("F_CROSSHAIR_TARGET", &["call", "access"]),
        ("M_SET_YAW", &["call"]),
        ("C_INTERACT_ENTITY_PKT", &["ref"]),
    ];
    for pr in probes.iter() {
        for e in evs {
            combat = concept_hit(e, pr.0, pr.1, &ctx);
            if combat.is_some() {
                break;
            }
        }
        if combat.is_some() {
            break;
        }
    }
    if combat.is_none() {
        combat = mcp_combat(evs);
    }
    let Some(combat) = combat else { return };
    let cl: StrList = cats.iter().map(|s| s.to_string()).collect();
    let sd: StrList = subs.iter().take(4).map(|s| dotted(s)).collect();
    let mut f = Finding::default();
    f.key = "client_layout".to_string();
    f.label = "Hile istemcisi modül yapısı".to_string();
    f.category = if game_jar { "KESIN_HILE" } else { "SUPHELI" }.to_string();
    f.explain = format!(
        "Kodda hile istemcilerine özgü menu kategorileri ({}), ortak bir modül sınıfından türemiş {} \
         sınıf ve oyuncu adına saldırı/bakış kodu birlikte bulundu{}.",
        join(&cl, ", "),
        subs.len(),
        if game_jar {
            "; üstelik bu yapı OYUN DOSYASININ İÇİNE gömülmüş (değiştirilmiş tam istemci)"
        } else {
            "; elle inceleyin"
        }
    );
    let mut u = Unit::default();
    u.unit = "jar".to_string();
    u.groups.push(vec![
        rw("hint", "-", &format!("kategoriler: {}", join(&cl, ", "))),
        rw(
            "ref",
            &base,
            &format!("{} modül sınıfı: {} ...", subs.len(), join(&sd, ", ")),
        ),
        rw(combat.kind, "-", &combat.detail),
    ]);
    f.units.push(u);
    res.findings.push(f);
}

fn obfuscation(res: &mut ScanResult, evs: &[&ClassEv]) {
    if res.official_fabric || evs.len() < 8 {
        return;
    }
    let mut outers: BTreeSet<&str> = BTreeSet::new();
    for e in evs {
        outers.insert(first_seg(&e.name, "$"));
    }
    let mut shorts: usize = 0;
    for o in &outers {
        if ulen(&last_seg(o, "/")) <= 2 {
            shorts += 1;
        }
    }
    if (shorts as f64) / (outers.len().max(1) as f64) >= 0.6 {
        let mut mc = false;
        for e in evs {
            if e.refs.iter().any(|r| r.starts_with("net/minecraft/")) {
                mc = true;
            }
            if mc {
                break;
            }
        }
        if mc {
            addf(
                res,
                "obfuscated",
                "Karartılmış (obfuscated) kod",
                "SUPHELI",
                "Sınıfların çoğu anlamsız kısa adlara sahip (a, b, aa ...). Hile clientleri kodlarını \
                 gizlemek için bunu kullanır; elle inceleyin.",
                vec![rw("ref", "-", &format!("{}/{} sınıf kısa adli", shorts, outers.len()))],
            );
        }
    }
}

fn run_signatures<'a>(
    res: &mut ScanResult,
    evs: &[&'a ClassEv],
    env_client: bool,
    client_mx: &BTreeSet<String>,
    has_via: bool,
) {
    let ctx = Ctx::new(evs);
    let nms = nm();
    let client_ok = |e: &ClassEv| -> bool {
        if env_client || client_mx.contains(&e.name) {
            return true;
        }
        if e.is_mixin {
            for t in &e.targets {
                if nms.client_only_classes.contains(t.as_str()) || starts_any(t, CLIENT_ONLY_PREFIXES) {
                    return true;
                }
            }
        }
        for r in &e.refs {
            if nms.client_only_classes.contains(r.as_str()) || starts_any(r, CLIENT_ONLY_PREFIXES) {
                return true;
            }
        }
        false
    };
    let accept = |sig: &Signature, members: &[&ClassEv], groups: &[RowGroup]| -> bool {
        if has_via {
            for e in members {
                for r in &e.refs {
                    if starts_any(r, VIA_REF_PREFIXES) {
                        return false;
                    }
                }
            }
        }
        if sig.side == "client" {
            let mut names: BTreeSet<&str> = BTreeSet::new();
            for g in groups {
                for x in g {
                    names.insert(x.cls.as_str());
                }
            }
            let mut byn: HashMap<&str, &ClassEv> = HashMap::new();
            for e in members {
                byn.insert(e.name.as_str(), e);
            }
            let mut any = false;
            for c in &names {
                if let Some(e) = byn.get(c) {
                    if client_ok(e) {
                        any = true;
                        break;
                    }
                }
            }
            if !any {
                return false;
            }
        }
        true
    };
    let mut units: Vec<(String, Vec<&'a ClassEv>)> = Vec::new();
    let mut ui: HashMap<String, usize> = HashMap::new();
    for e in evs {
        let outer = first_seg(&e.name, "$").to_string();
        let idx = match ui.get(&outer) {
            Some(&i) => i,
            None => {
                ui.insert(outer.clone(), units.len());
                units.push((outer, Vec::new()));
                units.len() - 1
            }
        };
        units[idx].1.push(e);
    }
    let jar_classes: HashSet<&str> = evs.iter().map(|e| e.name.as_str()).collect();
    fn unit_members<'u, 'a>(
        ui: &HashMap<String, usize>,
        units: &'u [(String, Vec<&'a ClassEv>)],
        u: &str,
    ) -> Option<&'u Vec<&'a ClassEv>> {
        ui.get(u).map(|&i| &units[i].1)
    }
    fn expand<'a>(
        unit_name: &str,
        members: &[&'a ClassEv],
        extra: &mut StrList,
        ui: &HashMap<String, usize>,
        units: &[(String, Vec<&'a ClassEv>)],
        jar_classes: &HashSet<&str>,
    ) -> Vec<&'a ClassEv> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        seen.insert(unit_name.to_string());
        let mut frontier: Vec<String> = vec![unit_name.to_string()];
        let mut out: Vec<&'a ClassEv> = members.to_vec();
        for _k in 0..2 {
            let mut nxt: Vec<String> = Vec::new();
            for u in &frontier {
                let Some(um) = unit_members(ui, units, u) else { continue };
                for e in um {
                    for c in &e.calls {
                        if !jar_classes.contains(c.owner.as_str()) {
                            continue;
                        }
                        let ou = first_seg(&c.owner, "$").to_string();
                        if !seen.contains(&ou) && seen.len() < 12 {
                            seen.insert(ou.clone());
                            nxt.push(ou.clone());
                            if let Some(om) = unit_members(ui, units, &ou) {
                                out.extend(om.iter().copied());
                            }
                        }
                    }
                }
            }
            frontier = nxt;
        }
        extra.clear();
        for s in &seen {
            if s != unit_name {
                extra.push(s.clone());
            }
        }
        out
    }

    let mut midx: Option<MethodIndex> = None;
    let mut chain_list: Vec<(usize, usize, EvP)> = Vec::new();

    let mut found: Vec<Finding> = Vec::new();
    let mut fidx: HashMap<&str, usize> = HashMap::new();
    let no_ex: SigGroup = &[];
    for sig in SIGNATURES.iter() {
        let mut hits: Vec<Unit> = Vec::new();
        let mut g: Vec<RowGroup> = Vec::new();
        let put = |hits: &mut Vec<Unit>, found: &mut Vec<Finding>, fidx: &mut HashMap<&'static str, usize>| {
            let mut f = Finding::default();
            f.key = sig.key.to_string();
            f.label = sig.label.to_string();
            f.category = sig.category.to_string();
            f.explain = sig.explain.to_string();
            f.unit_count = hits.len() as i32;
            if hits.len() > 6 {
                hits.truncate(6);
            }
            f.units = hits.clone();
            fidx.insert(sig.key, found.len());
            found.push(f);
        };
        if sig.scope == "method" {
            if !match_groups(sig.groups, sig.exclude, evs, &ctx, &mut g) {
                continue;
            }
            if sig.groups.len() == 1 && sig.unit_groups.is_empty() && !sig.chain_only {
                for e in evs {
                    let one: [&ClassEv; 1] = [e];
                    if match_groups(sig.groups, sig.exclude, &one, &ctx, &mut g) && accept(sig, &one, &g) {
                        let mut u = Unit::default();
                        u.unit = dotted(&e.name);
                        u.groups = g.clone();
                        hits.push(u);
                    }
                }
                if !hits.is_empty() {
                    put(&mut hits, &mut found, &mut fidx);
                }
                continue;
            }
            if midx.is_none() {
                let mut mi = MethodIndex::new(evs);
                for (ei, e) in evs.iter().enumerate() {
                    for (bi, b) in e.bodies.iter().enumerate() {
                        if b.code_len == 0 {
                            continue;
                        }
                        let cev = chain_ev(&mut mi, ei, bi);
                        chain_list.push((ei, bi, cev));
                    }
                }
                midx = Some(mi);
            }
            let mut seen_units: HashSet<String> = HashSet::new();
            for t in &chain_list {
                let e: &ClassEv = evs[t.0];
                let b = &e.bodies[t.1];
                let one: [&ClassEv; 1] = [t.2.as_ref()];
                let mut okm = match_groups(sig.groups, sig.exclude, &one, &ctx, &mut g);
                if okm && !sig.unit_groups.is_empty() {
                    let ue: Vec<&ClassEv> = match unit_members(&ui, &units, first_seg(&e.name, "$")) {
                        Some(um) => um.clone(),
                        None => vec![e],
                    };
                    let mut ug: Vec<RowGroup> = Vec::new();
                    if match_groups(sig.unit_groups, no_ex, &ue, &ctx, &mut ug) {
                        g.extend(ug);
                    } else {
                        okm = false;
                    }
                }
                if okm && accept(sig, &one, &g) {
                    let uname = format!("{}.{}", dotted(&e.name), b.name);
                    if seen_units.contains(&uname) {
                        continue;
                    }
                    seen_units.insert(uname.clone());
                    let mut u = Unit::default();
                    u.unit = uname;
                    u.groups = g.clone();
                    hits.push(u);
                }
            }
            if !hits.is_empty() {
                put(&mut hits, &mut found, &mut fidx);
            }
            continue;
        }
        for un in &units {
            if match_groups(sig.groups, sig.exclude, &un.1, &ctx, &mut g) && accept(sig, &un.1, &g) {
                let mut u = Unit::default();
                u.unit = dotted(&un.0);
                u.groups = g.clone();
                hits.push(u);
                continue;
            }
            let mut extra: StrList = Vec::new();
            let ext = expand(&un.0, &un.1, &mut extra, &ui, &units, &jar_classes);
            if !extra.is_empty() && match_groups(sig.groups, sig.exclude, &ext, &ctx, &mut g) && accept(sig, &ext, &g) {
                let mut u = Unit::default();
                u.unit = dotted(&un.0);
                u.merged = true;
                for x in &extra {
                    u.via.push(dotted(x));
                }
                u.groups = g.clone();
                hits.push(u);
            }
        }
        if hits.is_empty()
            && units.len() <= SMALL_MOD_UNITS
            && !evs.is_empty()
            && match_groups(sig.groups, sig.exclude, evs, &ctx, &mut g)
            && accept(sig, evs, &g)
        {
            let mut u = Unit::default();
            u.unit = "(tüm mod - işlev sınıflara dağıtılmış)".to_string();
            u.merged = true;
            u.groups = g.clone();
            hits.push(u);
        }
        if !hits.is_empty() {
            put(&mut hits, &mut found, &mut fidx);
        }
    }
    let mut removed: HashSet<&str> = HashSet::new();
    for sig in SIGNATURES.iter() {
        if !fidx.contains_key(sig.key) {
            continue;
        }
        for k in sig.suppressed_by.iter() {
            if fidx.contains_key(k) && !removed.contains(k) {
                removed.insert(sig.key);
                break;
            }
        }
    }
    for f in &found {
        if !removed.contains(f.key.as_str()) {
            res.findings.push(f.clone());
        }
    }
}

pub fn weak_to_notes(res: &mut ScanResult) {
    const WEAK: &[&str] = &[
        "encrypted_java",
        "hidden_classes",
        "fake_fabric",
        "obfuscated",
        "renamed_jar",
        "disguised_file",
    ];
    let mut keep: Vec<Finding> = Vec::new();
    let findings = std::mem::take(&mut res.findings);
    for f in findings {
        if in_list(&f.key, WEAK) {
            res.notes.push(format!(
                "Ek bilgi (tek başına hile kanıtı DEĞİL): {} - {}",
                f.label, f.explain
            ));
        } else {
            keep.push(f);
        }
    }
    res.findings = keep;
}

// ---------------------------------------------------------------------------------------------
// Kesinlik kontrolü: "KESİN HİLE" kararı yalnızca dosyanın hile olduğu KANITLANDIĞINDA verilir.
//
// Kanıt (tek başına yeter): bilinen hile istemcisinin kodu / eklenti API'si / kaynak kodu, hile
// istemcisi modül yapısı, iz silme aracı, oyuna kod enjekte eden yükleyici, kodunu gizleyip
// bellekte çalıştıran yükleyici, gizli Java agent, kod adlarında hile modül adları.
//
// Belirti (tek başına yetmez): davranış imzaları (Reach, KillAura ...) meşru modlarda da
// görülebilir (ölçek / savaş / görüntü modları). Davranış ancak BAĞIMSIZ ikinci bir kanıtla
// (kod karartma, gizli sınıf, şifreli kod, Java agent, kod içi hile adı) birlikte KESİN sayılır;
// aksi halde ŞÜPHELİ gösterilir ve yetkilinin elle kontrol etmesi istenir.
// ---------------------------------------------------------------------------------------------
const PROOF_KEYS: &[&str] = &[
    "known_client",
    "client_addon",
    "cheat_source",
    "client_layout",
    "handle_closer",
    "handle_closer_mod",
    "native_injector",
    "injector",
    "memory_loader",
    "hidden_loader",
    "packed_loader",
    "native_module_client",
];
const CONCEAL_KEYS: &[&str] = &["obfuscated", "hidden_classes", "encrypted_java", "fake_fabric"];

/// weak_to_notes'tan ÖNCE çağrılır: gizleme belirtileri bulgudan nota çevrilmeden önce toplanır.
pub fn concealment_labels(res: &ScanResult) -> StrList {
    let mut out: StrList = Vec::new();
    for f in &res.findings {
        if in_list(&f.key, CONCEAL_KEYS) && f.category != "BILGI" && !out.contains(&f.label) {
            out.push(f.label.clone());
        }
    }
    out
}

/// KESİN_HİLE kategorili bir davranış imzasının ailesi (aynı hilenin iki imzası tek aile sayılır).
fn behavior_family(key: &str) -> Option<&'static str> {
    let sig = SIGNATURES.iter().find(|s| s.key == key && s.category == "KESIN_HILE")?;
    Some(match sig.key {
        "reach_player" => "reach",
        "velocity_player" => "velocity",
        "nofall_packet" => "nofall",
        k => k,
    })
}

/// cheat_terms bulgusunda hile adının SINIF/METOT/ALAN ADINDA geçtiği farklı terim sayısı.
fn ident_term_count(f: &Finding) -> usize {
    let mut terms: BTreeSet<String> = BTreeSet::new();
    for u in &f.units {
        for g in &u.groups {
            for r in g {
                if r.detail.contains("(sınıf/metot/alan adı)") {
                    if let Some(t) = r.detail.split('\'').nth(1) {
                        terms.insert(t.to_string());
                    }
                }
            }
        }
    }
    terms.len()
}

pub fn certainty_gate(res: &mut ScanResult, conceal: &[String]) {
    let kesin: Vec<usize> = (0..res.findings.len())
        .filter(|&i| res.findings[i].category == "KESIN_HILE")
        .collect();
    if kesin.is_empty() {
        return;
    }
    let mut behaviors: BTreeSet<&'static str> = BTreeSet::new();
    let mut beh_labels: StrList = Vec::new();
    for &i in &kesin {
        if let Some(fam) = behavior_family(&res.findings[i].key) {
            if behaviors.insert(fam) {
                beh_labels.push(res.findings[i].label.clone());
            }
        }
    }
    let mut proof = false;
    for &i in &kesin {
        let f = &res.findings[i];
        if in_list(&f.key, PROOF_KEYS) || (f.key == "java_agent" && f.label.contains("gizli")) {
            proof = true;
        } else if f.key == "cheat_terms" {
            let n = ident_term_count(f);
            if n >= 2 || (n >= 1 && !behaviors.is_empty()) {
                proof = true;
            }
        }
    }
    if proof {
        return; // dosyanın hile olduğu kanıtlı: karar KESİN kalır
    }
    let mut support: StrList = conceal.to_vec();
    for &i in &kesin {
        let f = &res.findings[i];
        if (f.key == "java_agent" || f.key == "cheat_terms") && !support.contains(&f.label) {
            support.push(f.label.clone());
        }
    }
    if !behaviors.is_empty() && !support.is_empty() {
        let msg = format!(
            "  >> Kesinlik kontrolü: hile davranışı ({}) ile birlikte bağımsız bir kanıt daha bulundu ({}); \
             iki ayrı kanıt bir arada olduğu için KESİN sayıldı.",
            join(&beh_labels, ", "),
            join(&support, ", ")
        );
        for &i in &kesin {
            res.findings[i].explain.push_str(&msg);
        }
        return;
    }
    for &i in &kesin {
        let f = &mut res.findings[i];
        f.category = "SUPHELI".to_string();
        f.explain.push_str(
            "  >> Kesinlik kontrolü: bu bulgu tek başına hile olduğunu KANITLAMAZ; meşru modlar da benzer kod \
             içerebilir. Aynı dosyada bilinen hile kodu, hile modül adları ya da kod gizleme gibi ikinci bir \
             kanıt olmadığı için KESİN HİLE yerine ŞÜPHELİ gösterildi. Yetkili elle kontrol etmeli.",
        );
    }
    res.notes.push(format!(
        "Kesinlik kontrolü: {} bulgu KESİN HİLE'den ŞÜPHELİ'ye indirildi (tek başına kanıt değil, ikinci bir kanıt yok).",
        kesin.len()
    ));
}

fn pe_has(data: &[u8], word: &str) -> bool {
    if bcontains(data, word.as_bytes()) {
        return true;
    }
    let mut w16: Vec<u8> = Vec::with_capacity(word.len() * 2);
    for &c in word.as_bytes() {
        w16.push(c);
        w16.push(0);
    }
    bcontains(data, &w16)
}

pub fn pe_injector_check(data: &[u8], explain: &mut String, evidence: &mut StrList) -> bool {
    let jvm: [&str; 2] = [kw_jni_vms(), kw_jvm_dll()];
    const WR: &[&str] = &["WriteProcessMemory", "NtWriteVirtualMemory"];
    const TH: &[&str] = &[
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "RtlCreateUserThread",
        "QueueUserAPC",
        "SetWindowsHookEx",
    ];
    const GAME: &[&str] = &[
        "javaw.exe",
        "javaw",
        "Minecraft",
        "minecraft",
        "LWJGL",
        "lwjgl",
        "net/minecraft",
        "net.minecraft",
        "lunarclient",
        "Lunar Client",
        "Badlion",
    ];
    const GCLS: &[&str] = &[
        "net/minecraft/",
        "net/minecraft/client",
        "MinecraftClient",
        "net/minecraft/class_",
    ];
    if data.len() < 1024 || !data.starts_with(b"MZ") {
        return false;
    }
    let mut ev: StrList = Vec::new();
    for w in jvm.iter() {
        if pe_has(data, w) {
            ev.push(w.to_string());
        }
    }
    if ev.is_empty() {
        return false;
    }
    if is_own_component(data) {
        return false;
    }
    let pick_has =
        |list: &[&str]| -> StrList { list.iter().filter(|w| pe_has(data, w)).map(|w| w.to_string()).collect() };
    let game = pick_has(GAME);
    let wr = pick_has(WR);
    let th = pick_has(TH);
    let gcls = pick_has(GCLS);
    let g3: StrList = game.iter().take(3).cloned().collect();
    if !wr.is_empty() && !th.is_empty() && !game.is_empty() {
        *explain = format!(
            "başka bir sürecin belleğine yazıp ({}) uzak is parçacığı başlatıyor ({}); JVM'i ({}) ve Minecraft/javaw'i ({}) hedefliyor - Java oyununa dışarıdan kod enjekte eden program.",
            join(&wr, ", "),
            join(&th, ", "),
            join(&ev, ", "),
            join(&g3, ", ")
        );
        *evidence = ev.clone();
        evidence.extend(wr.iter().cloned());
        evidence.extend(th.iter().cloned());
        evidence.extend(g3.iter().cloned());
        return true;
    }
    if pe_has(data, kw_jni_vms()) && !gcls.is_empty() {
        let c3: StrList = gcls.iter().take(3).cloned().collect();
        *explain = format!(
            "çalışan Java sanal makinesini içten ele geçiriyor ({}) ve Minecraft sınıflarına erişiyor ({}) - oyunun içine yüklenen hile kodu (DLL yükü).",
            kw_jni_vms(),
            join(&c3, ", ")
        );
        *evidence = vec![kw_jni_vms().to_string()];
        evidence.extend(c3);
        return true;
    }
    false
}

fn rfind_at_or_before(d: &[u8], pat: &[u8], pos: usize) -> Option<usize> {
    let end = pos.saturating_add(pat.len()).min(d.len());
    memchr::memmem::rfind(&d[..end], pat)
}

pub fn recover_zip(data: &[u8], out: &mut Bytes) -> bool {
    let d = data;
    let mut i = memchr::memmem::rfind(d, b"PK\x05\x06");
    while let Some(ii) = i {
        if ii + 22 <= d.len() {
            let clen = rd16(&d[ii + 20..]);
            let end = d.len().min(ii + 22 + clen as usize);
            let cand = &d[..end];
            let mut names: Vec<String> = Vec::new();
            if zip_opens(cand, Some(&mut names)) && !names.is_empty() {
                *out = cand.to_vec();
                return true;
            }
        }
        if ii == 0 {
            break;
        }
        i = rfind_at_or_before(d, b"PK\x05\x06", ii - 1);
    }
    let mut zw = ZipWriter::new();
    let mut n_ok: usize = 0;
    let mut total: u64 = 0;
    let mut p = memchr::memmem::find(d, b"PK\x03\x04");
    while let Some(pp) = p {
        if n_ok >= 60000 {
            break;
        }
        if pp + 30 <= d.len() {
            let h = &d[pp..];
            let flags = rd16(&h[6..]);
            let method = rd16(&h[8..]);
            let csize = rd32(&h[18..]);
            let nlen = rd16(&h[26..]) as usize;
            let xlen = rd16(&h[28..]) as usize;
            let nstart = d.len().min(pp + 30);
            let name = utf8_decode(&d[nstart..d.len().min(nstart + nlen)], 0);
            let start = pp + 30 + nlen + xlen;
            let mut have = false;
            let mut body: Bytes = Vec::new();
            if start <= d.len() {
                if method == 0 && csize != 0 && (flags & 8) == 0 {
                    body = d[start..d.len().min(start + csize as usize)].to_vec();
                    have = true;
                } else if method == 8 {
                    let len = if csize != 0 && (flags & 8) == 0 {
                        csize as usize
                    } else {
                        MAX_INNER as usize
                    };
                    have = inflate_raw(
                        &d[start..d.len().min(start.saturating_add(len))],
                        &mut body,
                        MAX_INNER,
                        None,
                    );
                }
            }
            if have && (flags & 1) == 0 && !name.is_empty() && !name.ends_with('/') {
                total += body.len() as u64;
                if total > MAX_INNER {
                    break;
                }
                zw.add(&name, &body);
                n_ok += 1;
            }
        }
        p = memchr::memmem::find(&d[pp + 4..], b"PK\x03\x04").map(|x| x + pp + 4);
    }
    if n_ok == 0 {
        return false;
    }
    *out = zw.finish();
    true
}

fn rstrip_crlf(b: &[u8]) -> Bytes {
    let mut e = b.len();
    while e > 0 && (b[e - 1] == b'\r' || b[e - 1] == b'\n') {
        e -= 1;
    }
    b[..e].to_vec()
}
fn crlf_to_lf(b: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'\r' && b.get(i + 1) == Some(&b'\n') {
            out.push(b'\n');
            i += 2;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

pub fn untext_archive(data: &[u8], out: &mut Bytes, how: &mut String) -> bool {
    if data.is_empty() || data.len() as u64 > MAX_INNER * 3 {
        return false;
    }
    let mut texts: Vec<(String, &'static str)> = Vec::new();
    let d = data;
    let bom16 = d.len() >= 2 && ((d[0] == 0xff && d[1] == 0xfe) || (d[0] == 0xfe && d[1] == 0xff));
    let le16 = d.len() >= 8 && d[..8] == *b"P\0K\0\x03\0\x04\0";
    let be16 = d.len() >= 8 && d[..8] == *b"\0P\0K\0\x03\0\x04";
    if bom16 || le16 || be16 {
        let mut t = String::new();
        let le = if bom16 { d[0] == 0xff } else { le16 };
        let src = if bom16 { &d[2..] } else { d };
        if utf16_strict(src, le, &mut t) {
            texts.push((t, "UTF-16 metin"));
        }
    } else {
        let body: &[u8] = if d.len() >= 3 && d[..3] == *b"\xef\xbb\xbf" {
            &d[3..]
        } else {
            d
        };
        let head = &body[..body.len().min(64)];
        let tail = &body[if body.len() > 256 { body.len() - 256 } else { 0 }..];
        if !bcontains(head, b"PK\x03\x04") && !bcontains(tail, b"PK\x05\x06") {
            return false;
        }
        if !utf8_valid(body, false) {
            return false;
        }
        texts.push((String::from_utf8_lossy(body).into_owned(), "UTF-8 metin"));
    }
    for tx in &texts {
        let mut raw: Bytes = Vec::new();
        if !chars_to_bytes(&tx.0, &mut raw) || raw == data {
            continue;
        }
        let c2 = rstrip_crlf(&raw);
        let c3 = crlf_to_lf(&raw);
        for cand in [&raw, &c2, &c3] {
            let mut z = ZipReader::new();
            if z.open(cand) && !z.entries().is_empty() && z.testzip() {
                *out = cand.clone();
                *how = tx.1.to_string();
                return true;
            }
        }
    }
    false
}

rx_static!(rx_yml_main, r#"^main\s*:\s*['"]?([A-Za-z0-9_.$]+)"#, Rx::M);
rx_static!(rx_json_main, r#""main"\s*:\s*"([A-Za-z0-9_.$]+)""#, 0);

const ASSET_EXT: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".ogg", ".mp3", ".wav", ".mp4", ".webm", ".ttf", ".otf", ".woff", ".woff2", ".zip", ".gz",
    ".xz", ".zst", ".7z", ".rar", ".bz2", ".jar", ".webp", ".ico", ".pack", ".nbt",
];
const ASSET_MAGIC: &[&[u8]] = &[
    b"\x89PNG",
    b"\xff\xd8\xff",
    b"OggS",
    b"RIFF",
    b"ID3",
    b"PK\x03\x04",
    b"\x1f\x8b",
    b"7z\xbc\xaf",
    b"Rar!",
    b"\xfd7zXZ",
    b"BZh",
    b"OTTO",
    b"wOFF",
    b"GIF8",
    b"BM",
    b"\x00\x01\x00\x00",
];
const CLIENT_MARKS: &[&str] = &[
    "net/minecraft/client/",
    "com/mojang/blaze3d/",
    "org/lwjgl/",
    "net/minecraft/class_",
    "Lorg/spongepowered/asm/mixin/Mixin;",
    "org/spongepowered/asm/mixin/injection/",
    "com/sun/tools/attach/",
    "com.sun.tools.attach",
    "java/lang/instrument/",
    "net/bytebuddy/agent/",
    "net/fabricmc/",
    "net/minecraftforge/",
    "net/neoforged/",
    "cpw/mods/",
    "org/quiltmc/",
];

struct NestedArch {
    n: String,
    b: Bytes,
    why: String,
}

pub fn scan_jar_bytes(
    display_name: &str,
    data_in: &[u8],
    depth: i32,
    path_label: &str,
    disk_mode: bool,
    stop: Option<&StopFlag>,
) -> ScanResult {
    let stopped = || stop.is_some_and(|s| s.is_set());
    let mut res = new_result(display_name, data_in, path_label);
    let mut rec: Bytes = Vec::new();
    let mut zf = ZipReader::new();
    let mut data: &[u8] = data_in;
    if !zf.open(data) {
        let e = zf.error().to_string();
        let mut txt: Bytes = Vec::new();
        let mut how = String::new();
        let is_txt = untext_archive(data, &mut txt, &mut how);
        let ok;
        if is_txt {
            rec = txt;
            ok = true;
            res.notes.push(format!(
                "Arşiv bir metin düzenleyiciyle {} olarak kaydedilmiş / bu yolla bozulmuş (Java bu haliyle açamaz ama tek adımda eski \
                 haline getirilebilir - gizleme); içerik geri çevrilerek okundu.",
                how
            ));
            res.text_encoded = how;
        } else {
            ok = recover_zip(data, &mut rec);
        }
        if !ok {
            res.error = format!("Arşiv açılamadı: {}", e);
            res.notes
                .push("Arşiv açılamadı (bozuk / şifreli) - içerik incelenemedi.".to_string());
            res.relevant = false;
            return res;
        }
        if !is_txt {
            res.notes.push(
                "Arşivin yapısı bozulmuş / sonuna-başına veri eklenmiş (gizleme); içerik onarılarak \
                 okundu."
                    .to_string(),
            );
        }
        data = &rec;
        zf = ZipReader::new();
        if !zf.open(data) {
            res.error = format!("Arşiv açılamadı: {}", zf.error());
            res.relevant = false;
            return res;
        }
    }

    let mut files: Files = Vec::new();
    let mut class_entries: Vec<(String, Bytes)> = Vec::new();
    let mut sources: Vec<(String, Bytes)> = Vec::new();
    let mut pe_entries: Vec<(String, Bytes)> = Vec::new();
    let mut hidden_classes: StrList = Vec::new();
    let mut encrypted_java: StrList = Vec::new();
    let mut opaque_names: StrList = Vec::new();
    let mut opaque_bytes: u64 = 0;
    let mut nested: Vec<NestedArch> = Vec::new();
    let mut raw_mc = false;
    let unc_budget: u64 = (1536u64 << 20).min((256u64 << 20).max((data.len() as u64).saturating_mul(25)));
    let mut unc_total: u64 = 0;
    for info in zf.entries() {
        if stopped() {
            break;
        }
        let n = &info.name;
        if info.is_dir() || info.usize > MAX_INNER {
            continue;
        }
        let low = py_lower(n);
        if info.flags & 0x1 != 0 {
            if low.ends_with(".class") || low.ends_with(".jar") {
                encrypted_java.push(n.clone());
            }
            continue;
        }
        if unc_total >= unc_budget || info.usize > unc_budget - unc_total {
            res.notes.push(format!(
                "Arşiv açıldığında aşırı büyüyor (sıkıştırma bombası niteliğinde): ilk {} MB okundu, \
                 kalan girdiler bellek güvenliği için atlandı.",
                unc_total >> 20
            ));
            break;
        }
        let mut b: Bytes = Vec::new();
        let mut err = String::new();
        if !zf.read(
            info,
            &mut b,
            Some(&mut err),
            None,
            MAX_INNER.min(unc_budget - unc_total),
        ) {
            res.notes
                .push(format!("Okunamayan girdi: {} ({})", n, uslice(&err, 80)));
            continue;
        }
        unc_total += b.len() as u64;
        let cafe = b.len() >= 4 && b[..4] == [0xca, 0xfe, 0xba, 0xbe];
        if low.ends_with(".class") {
            if cafe {
                class_entries.push((n.clone(), b));
            }
            continue;
        }
        if cafe {
            class_entries.push((n.clone(), b));
            hidden_classes.push(n.clone());
            continue;
        }
        if (low.ends_with(".java") || low.ends_with(".kt")) && b.len() < 400000 && sources.len() < 20000 {
            sources.push((n.clone(), b));
            continue;
        }
        if bstarts(&b, b"PK\x03\x04") {
            nested.push(NestedArch {
                n: n.clone(),
                b,
                why: String::new(),
            });
            continue;
        }
        if bstarts(&b, b"\x1f\x8b") {
            let mut dd: Bytes = Vec::new();
            if gunzip(&b, &mut dd, 1u64 << 34, None) && bstarts(&dd, b"PK\x03\x04") {
                nested.push(NestedArch {
                    n: n.clone(),
                    b: dd,
                    why: "gzip içine gizlenmiş arşiv".to_string(),
                });
                continue;
            }
        }
        if bstarts(&b, b"MZ") && b.len() > 1024 {
            pe_entries.push((n.clone(), b));
            continue;
        }
        if b.len() >= 4096 && opaque_bytes < (1u64 << 32) {
            let mut known = ends_any(&low, ASSET_EXT);
            if !known {
                for m in ASSET_MAGIC {
                    if !m.is_empty() && b.len() >= m.len() && b[..m.len()] == **m {
                        known = true;
                        break;
                    }
                }
            }
            if !known && b.len() >= 12 && &b[4..8] == b"ftyp" {
                known = true;
            }
            if !known && is_der_crypto_blob(&b) {
                known = true; // sertifika / jar imzası / anahtar deposu (yapısal)
            }
            if !known && shannon_entropy(&b) >= 7.5 {
                opaque_bytes += b.len() as u64;
                if opaque_names.len() < 12 {
                    opaque_names.push(format!("{} ({:.1} KB)", n, b.len() as f64 / 1024.0));
                }
            }
        }
        if (low.ends_with(".json")
            || low.ends_with(".toml")
            || low.ends_with(".mf")
            || low.ends_with(".properties")
            || low.ends_with(".cfg")
            || low.ends_with(".yml")
            || in_list(&low, SERVER_PLUGIN_FILES))
            && b.len() < 4000000
        {
            match files.iter().position(|kv| kv.0 == *n) {
                Some(i) => files[i].1 = b,
                None => files.push((n.clone(), b)),
            }
        }
    }
    for ce in &class_entries {
        if !raw_mc && has_mc_marker(&ce.1) {
            raw_mc = true;
        }
    }

    let meta = parse_meta(&files);
    res.meta = meta.clone();
    res.class_count = class_entries.len() as i32;
    let mut is_server_plugin = false;
    for kv in &files {
        if in_list(&py_lower(&kv.0), SERVER_PLUGIN_FILES) {
            is_server_plugin = true;
        }
    }
    let manifest = match fget(&files, "META-INF/MANIFEST.MF") {
        Some(b) => utf8_decode(b, 1),
        None => String::new(),
    };
    let mut agent = AgentMatch::default();
    if let Some(m) = rx_agent().search(manifest.as_bytes(), 0) {
        agent.ok = true;
        agent.kind = m.group(1);
        agent.cls = m.group(2);
    }

    let mut loader_marks = false;
    for ce in &class_entries {
        if INJECT_MARKERS.iter().any(|mk| bcontains(&ce.1, mk.as_bytes())) {
            loader_marks = true;
        }
        if loader_marks {
            break;
        }
    }
    let shallow = disk_mode && !raw_mc && !meta.id.truthy && !agent.ok;
    let mut refmap: Refmap = HashMap::new();
    if !shallow {
        refmap = load_refmaps(&files, &meta);
    }
    let mut evp: Vec<EvP> = Vec::new();
    let mut bad = 0i32;
    let nms = nm();
    for ce in &class_entries {
        if stopped() {
            break;
        }
        let n = &ce.0;
        let b = &ce.1;
        if n.starts_with("META-INF/versions/") || n.ends_with("module-info.class") {
            continue;
        }
        if shallow {
            let low_b = b.to_ascii_lowercase();
            let mut keep = false;
            for t in STRONG_CHEAT_TERMS.iter() {
                if bcontains(&low_b, t.as_bytes()) {
                    keep = true;
                    break;
                }
            }
            if !keep && starts_any(n, &nms.known_pfx) {
                keep = true;
            }
            if !keep {
                for p in &nms.known_api_bytes {
                    if bcontains(b, p.as_bytes()) {
                        keep = true;
                        break;
                    }
                }
            }
            if !keep {
                for mk in INJECT_MARKERS {
                    if bcontains(b, mk.as_bytes()) {
                        keep = true;
                        break;
                    }
                }
            }
            if !keep && loader_marks {
                for a in LOADER_AUX {
                    if bcontains(&low_b, a.as_bytes()) {
                        keep = true;
                        break;
                    }
                }
            }
            if !keep {
                continue;
            }
        }
        match build_class_ev(n, b, &refmap) {
            Ok(e) => evp.push(e),
            Err(_) => bad += 1,
        }
    }
    if bad != 0 && !shallow {
        res.notes.push(format!(
            "{} sınıf ayrıştırılamadı (bozuk/korumalı bytecode olabilir).",
            bad
        ));
    }
    let evs: Vec<&ClassEv> = evp.iter().map(|e| e.as_ref()).collect();

    let all_names: StrList = evs.iter().map(|e| e.name.clone()).collect();
    {
        let mut pk: BTreeMap<String, i32> = BTreeMap::new();
        for ce in &class_entries {
            let n = &ce.0;
            if n.starts_with("META-INF/")
                || n.starts_with("net/minecraft/")
                || n.starts_with("com/mojang/")
                || n.starts_with("java/")
                || n.starts_with("javax/")
                || n.starts_with("kotlin/")
                || n.starts_with("org/spongepowered/")
                || n.starts_with("net/fabricmc/")
            {
                continue;
            }
            let mut dir: String = match n.rfind('/') {
                None => "(paketsiz)".to_string(),
                Some(sl) => n[..sl].to_string(),
            };
            let mut pos: Option<usize> = Some(0);
            for _k in 0..3 {
                let Some(pp) = pos else { break };
                pos = dir.get(pp + 1..).and_then(|s| s.find('/')).map(|x| x + pp + 1);
            }
            if let Some(pp) = pos {
                dir.truncate(pp);
            }
            *pk.entry(dir).or_insert(0) += 1;
        }
        let mut v: Vec<(i32, String)> = pk.into_iter().map(|(k, c)| (c, k)).collect();
        v.sort_by(|a, b| if a.0 != b.0 { b.0.cmp(&a.0) } else { a.1.cmp(&b.1) });
        for it in v.iter().take(8) {
            res.pkg_summary.push(format!("{} ({} sınıf)", dotted(&it.1), it.0));
        }
    }
    let mut uses_server_api = false;
    let mut uses_client_api = false;
    for e in &evs {
        for r in &e.refs {
            if !uses_server_api && starts_any(r, SERVER_API_PREFIXES) {
                uses_server_api = true;
            }
            if !uses_client_api && (starts_any(r, CLIENT_ONLY_PREFIXES) || nms.client_only_classes.contains(r.as_str()))
            {
                uses_client_api = true;
            }
        }
    }
    is_server_plugin = (is_server_plugin || uses_server_api) && !uses_client_api;
    let mut is_vanilla = false;
    for n in &all_names {
        if n == "net/minecraft/client/main/Main"
            || n == "net/minecraft/server/Main"
            || n == "net/minecraft/bundler/Main"
            || n == "net/minecraft/data/Main"
        {
            is_vanilla = true;
        }
    }
    if is_vanilla {
        res.kind = "Minecraft oyun dosyası".to_string();
    } else if is_server_plugin {
        res.kind = "Sunucu eklentisi (plugin)".to_string();
    }

    let mut verified_plugin = false;
    let mut plugin_desc = String::new();
    let mut plugin_main = String::new();
    if !is_vanilla
        && !meta.id.truthy
        && !agent.ok
        && hidden_classes.is_empty()
        && encrypted_java.is_empty()
        && opaque_bytes < (64u64 << 10)
    {
        for kv in &files {
            let ln = py_lower(&kv.0);
            if !in_list(&ln, SERVER_PLUGIN_FILES) {
                continue;
            }
            let txt = utf8_decode(&kv.1, 1);
            let m = if ln.ends_with(".json") {
                rx_json_main().search(txt.as_bytes(), 0)
            } else {
                rx_yml_main().search(txt.as_bytes(), 0)
            };
            if let Some(m) = m {
                plugin_desc = kv.0.clone();
                plugin_main = replace_all(&m.group(1), ".", "/");
                break;
            }
        }
        let mut client_mark = uses_client_api;
        if !plugin_main.is_empty() && !client_mark {
            for ce in &class_entries {
                if CLIENT_MARKS.iter().any(|mk| bcontains(&ce.1, mk.as_bytes())) {
                    client_mark = true;
                }
                if client_mark {
                    break;
                }
            }
        }
        let mut mixin_cfg = false;
        for kv in &files {
            if py_lower(&kv.0).ends_with("mixins.json") {
                mixin_cfg = true;
            }
        }
        let mut bad_pe = false;
        if !plugin_main.is_empty() && !client_mark {
            for pe in &pe_entries {
                let mut ex = String::new();
                let mut evd: StrList = Vec::new();
                if pe_injector_check(&pe.1, &mut ex, &mut evd) {
                    bad_pe = true;
                    break;
                }
            }
        }
        let mut main_ok = false;
        if !plugin_main.is_empty() && !client_mark && !mixin_cfg && !bad_pe {
            let find_cls = |internal: &str| -> Option<&Bytes> {
                let want = format!("{}.class", internal);
                class_entries.iter().find(|ce| ce.0 == want).map(|ce| &ce.1)
            };
            let mut cur = plugin_main.clone();
            let mut depth = 0;
            while depth < 6 && !main_ok {
                let Some(cb) = find_cls(&cur) else { break };
                if depth == 0 && bcontains(cb, b"Lcom/velocitypowered/api/plugin/Plugin;") {
                    main_ok = true;
                    break;
                }
                let ev = match build_class_ev(&format!("{}.class", cur), cb, &refmap) {
                    Ok(e) => e,
                    Err(_) => break,
                };
                let sup = replace_all(&ev.super_, ".", "/");
                if sup == "org/bukkit/plugin/java/JavaPlugin" || sup == "net/md_5/bungee/api/plugin/Plugin" {
                    main_ok = true;
                } else if sup.is_empty() || sup.starts_with("java/") {
                    break;
                } else {
                    cur = sup;
                }
                depth += 1;
            }
        }
        verified_plugin = main_ok;
    }

    let mut verified_server = false;
    let mut server_label = String::new();
    let mut server_id = String::new();
    {
        let mut mclass_orig = String::new();
        let mut mclass = String::new();
        if let Some(m) = rx_main_class().search(manifest.as_bytes(), 0) {
            mclass_orig = replace_all(&m.group(1), ".", "/");
            mclass = py_lower(&mclass_orig);
        }
        let main_hit =
            !mclass.is_empty() && in_list(&mclass, SERVER_BOOTSTRAP_MAINS) && all_names.contains(&mclass_orig);
        let mut cls_hit = String::new();
        for want in SERVER_BOOTSTRAP_CLASSES {
            if all_names.iter().any(|n| n == want) {
                cls_hit = want.to_string();
                break;
            }
        }
        let has_identity = main_hit || !cls_hit.is_empty();
        if has_identity && !uses_client_api && !meta.id.truthy {
            let mut client_cap = false;
            for ce in &class_entries {
                if SERVER_CLIENT_DISQUALIFY
                    .iter()
                    .any(|mk| bcontains(&ce.1, mk.as_bytes()))
                {
                    client_cap = true;
                }
                if client_cap {
                    break;
                }
            }
            if !client_cap {
                for kv in &files {
                    let l = py_lower(&kv.0);
                    if l.ends_with("mixins.json") || l == "fabric.mod.json" || l.ends_with("mods.toml") {
                        client_cap = true;
                        break;
                    }
                }
            }
            if !client_cap {
                verified_server = true;
                server_id = if main_hit {
                    format!("ana sınıf {}", dotted(&mclass))
                } else {
                    format!("başlatıcı sınıfı {}", dotted(&cls_hit))
                };
                if mclass.contains("paperclip") || all_names.iter().any(|n| n == "io/papermc/paperclip/Paperclip") {
                    server_label = "Paper/Spigot sunucu yazılımı (paperclip başlatıcı)".to_string();
                } else if mclass.contains("velocity") {
                    server_label = "Velocity proxy yazılımı".to_string();
                } else if mclass.contains("bungee") {
                    server_label = "BungeeCord/Waterfall proxy yazılımı".to_string();
                } else if mclass.contains("craftbukkit") {
                    server_label = "CraftBukkit/Spigot sunucu yazılımı".to_string();
                } else if mclass.contains("minecraft/server") || mclass.contains("minecraft/bundler") {
                    server_label = "Vanilla Minecraft sunucu yazılımı".to_string();
                } else {
                    server_label = "Minecraft sunucu / proxy yazılımı".to_string();
                }
            }
        }
    }

    let mut mod_evs: Vec<&ClassEv> = Vec::new();
    for e in &evs {
        let n = e.name.as_str();
        if n.starts_with("net/minecraft/") || n.starts_with("com/mojang/") {
            continue;
        }
        if is_vanilla && !n.contains('/') {
            continue;
        }
        if starts_any(n, FRAMEWORK_PREFIXES) && !e.is_mixin {
            continue;
        }
        mod_evs.push(e);
    }

    {
        let mut rows: RowGroup = Vec::new();
        let mut seen_clients: BTreeSet<String> = BTreeSet::new();
        for e in &evs {
            if !starts_any(&e.name, &nms.known_pfx) {
                continue;
            }
            for kc in KNOWN_CLIENTS.iter() {
                if e.name.starts_with(kc.0) && !seen_clients.contains(kc.1) {
                    seen_clients.insert(kc.1.to_string());
                    rows.push(rw(
                        "ref",
                        &e.name,
                        &format!("{} paketi: {}", kc.1, replace_all(kc.0, "/", ".")),
                    ));
                }
            }
        }
        if !rows.is_empty() {
            rows.truncate(10);
            let names: StrList = seen_clients.iter().cloned().collect();
            addf(
                &mut res,
                "known_client",
                &format!("Bilinen hile client'i: {}", join(&names, ", ")),
                "KESIN_HILE",
                "JAR, bilinen bir hile istemcisinin / botunun kod paketini içeriyor.",
                rows,
            );
        }
    }
    {
        let mut arows: RowGroup = Vec::new();
        let mut anames: BTreeSet<String> = BTreeSet::new();
        for kc in KNOWN_CLIENT_APIS.iter() {
            let own = all_names.iter().any(|n| n.starts_with(kc.0));
            if own {
                continue;
            }
            let mut users: Vec<(String, String)> = Vec::new();
            let mut ucls: BTreeSet<String> = BTreeSet::new();
            for e in &mod_evs {
                for r in &e.refs {
                    if r.starts_with(kc.0) {
                        users.push((e.name.clone(), r.clone()));
                        ucls.insert(e.name.clone());
                    }
                }
            }
            if !users.is_empty() && ucls.len() >= 2 {
                anames.insert(kc.1.to_string());
                for u in users.iter().take(4) {
                    arows.push(rw("ref", &u.0, &format!("{} kullanıyor: {}", kc.1, u.1)));
                }
            }
        }
        if !arows.is_empty() {
            arows.truncate(10);
            let names: StrList = anames.iter().cloned().collect();
            addf(
                &mut res,
                "client_addon",
                &format!("Hile client'i eklentisi: {}", join(&names, ", ")),
                "KESIN_HILE",
                "JAR, bir hile istemcisinin eklenti (addon/plugin) API'sini kullanıyor; yalnızca o hile \
                 istemcisiyle birlikte çalışan ek hile modülleridir.",
                arows,
            );
        }
    }
    if !encrypted_java.is_empty() {
        let mut g: RowGroup = Vec::new();
        for e in encrypted_java.iter().take(10) {
            g.push(rw("hint", "-", e));
        }
        addf(
            &mut res,
            "encrypted_java",
            "Parola ile şifrelenmiş Java kodu",
            "SUPHELI",
            "Arşivdeki Java dosyaları parola ile şifrelenmiş; içeriği okunamıyor. Java bunları doğrudan \
             çalıştıramaz, yalnızca özel bir yükleyici açabilir - kod gizleme yöntemidir.",
            g,
        );
    }
    let mut hidden_mc: StrList = Vec::new();
    {
        let hs: HashSet<&str> = hidden_classes.iter().map(|s| s.as_str()).collect();
        for ce in &class_entries {
            if hs.contains(ce.0.as_str()) && has_mc_marker(&ce.1) {
                hidden_mc.push(ce.0.clone());
            }
        }
        if !hidden_mc.is_empty() {
            let mut g: RowGroup = Vec::new();
            for h in hidden_mc.iter().take(10) {
                g.push(rw("hint", "-", h));
            }
            addf(
                &mut res,
                "hidden_classes",
                "Uzantısı gizlenmiş Minecraft kodu",
                if hidden_mc.len() >= 2 { "KESIN_HILE" } else { "SUPHELI" },
                "Minecraft'a erişen Java sınıf dosyaları .class dışında bir uzantıyla saklanmış; özel bir \
                 yükleyiciyle gizlice çalıştırılmak üzere paketlenmiş kod (ghost client yöntemi).",
                g,
            );
        }
    }
    keyword_game_client(&mut res, &class_entries);

    let mut outers: BTreeSet<String> = BTreeSet::new();
    for ce in &class_entries {
        if ce.0.starts_with("META-INF/") {
            continue;
        }
        let mut n = ce.0.clone();
        let from = match n.rfind('/') {
            None => 0,
            Some(sl) => sl + 1,
        };
        if let Some(dot) = n.get(from..).and_then(|s| s.find('.')).map(|x| x + from) {
            n.truncate(dot);
        }
        outers.insert(first_seg(&n, "$").to_string());
    }
    let mut shortc: usize = 0;
    for o in &outers {
        if ulen(&last_seg(o, "/")) <= 2 {
            shortc += 1;
        }
    }
    let obf_ratio = if outers.len() >= 5 {
        shortc as f64 / outers.len() as f64
    } else {
        0.0
    };
    let mut mentions_game = false;
    for e in &evs {
        for s in &e.strings {
            let l = py_lower(s);
            if has_any(&l, GAME_TARGET_WORDS) {
                mentions_game = true;
                break;
            }
        }
        if mentions_game {
            break;
        }
    }

    let is_mod_meta = meta.id.truthy;
    let trust = classify_trusted(
        if meta.id.truthy { &meta.id.s } else { "" },
        &all_names,
        if agent.ok { &agent.cls } else { "" },
    );
    if trust.infra {
        res.trusted_infra = true;
        res.trust_label = trust.label.clone();
        res.notes.push(format!("{}: {}", trust.label, trust.note));
    }
    let qp_agent =
        !trust.infra && agent.ok && verify_quickplay_launcher_agent(&evs, &agent, obf_ratio, &hidden_classes, None);
    loader_checks(
        &mut res,
        &evs,
        &agent,
        raw_mc,
        mentions_game,
        obf_ratio,
        &hidden_classes,
        &pe_entries,
        is_mod_meta,
        trust.infra || qp_agent,
        opaque_bytes,
        &opaque_names,
    );
    let mut loader_found = false;
    for f in &res.findings {
        if f.key == "injector" || f.key == "java_agent" || f.key == "hidden_loader" {
            loader_found = true;
        }
    }
    if !loader_found {
        let mut indy = 0i32;
        for e in &evs {
            indy += e.indy_custom;
        }
        memory_loader(&mut res, &evs, is_mod_meta, obf_ratio >= 0.6 || indy >= 5);
    }
    native_module_client(&mut res, &evs, is_mod_meta || raw_mc);
    handle_closer(&mut res, &class_entries, raw_mc || mentions_game);
    cheat_source(&mut res, &sources);

    let mid = py_lower(if meta.id.truthy { &meta.id.s } else { "" });
    let mid_dash = replace_all(&mid, "_", "-");
    let id_is_fabric = in_list(&mid, FABRIC_OFFICIAL_IDS)
        || starts_any(&mid, FABRIC_OFFICIAL_ID_PREFIXES)
        || in_list(&mid_dash, FABRIC_OFFICIAL_IDS)
        || starts_any(&mid_dash, FABRIC_OFFICIAL_ID_PREFIXES);
    let mut only_allowed = !all_names.is_empty();
    for c in &all_names {
        if !starts_any(c, FABRIC_ALLOWED_PREFIXES) {
            only_allowed = false;
            break;
        }
    }
    if id_is_fabric && (only_allowed || all_names.is_empty()) && hidden_mc.is_empty() {
        res.official_fabric = true;
    } else if id_is_fabric && !all_names.is_empty() && !only_allowed {
        let mut g: RowGroup = Vec::new();
        for c in &all_names {
            if g.len() >= 5 {
                break;
            }
            if !starts_any(c, FABRIC_ALLOWED_PREFIXES) {
                g.push(rw("ref", c, "Fabric dışı sınıf"));
            }
        }
        addf(
            &mut res,
            "fake_fabric",
            "Sahte Fabric modülü",
            "SUPHELI",
            &format!(
                "Mod kimliği resmi bir Fabric modülü gibi görünüyor ({}) ama içinde Fabric'e ait olmayan sınıflar var.",
                mid
            ),
            g,
        );
    }
    for e in &mod_evs {
        if !e.is_mixin {
            continue;
        }
        let mut mi = MixinInfo::default();
        mi.cls = dotted(&e.name);
        for t in &e.targets {
            mi.targets.push(format!("{} ({})", short_cls(t), t));
        }
        mi.targets.sort();
        for m in e.mixin_methods.iter().take(12) {
            mi.injections.push(m.clone());
        }
        res.mixins.push(mi);
    }
    if !res.official_fabric && !res.trusted_infra && !shallow {
        let mut has_via = false;
        for e in &evs {
            if e.name.starts_with("com/viaversion/viaversion/") {
                has_via = true;
                break;
            }
        }
        if !has_via {
            for ns in &nested {
                if rx_via().search(py_lower(&ns.n).as_bytes(), 0).is_some() {
                    has_via = true;
                    break;
                }
            }
        }
        run_signatures(
            &mut res,
            &mod_evs,
            meta.environment.s == "client" && meta.environment.truthy,
            &client_mixins(&files, &meta),
            has_via,
        );
    }
    if !is_server_plugin {
        if is_vanilla {
            cheat_terms(&mut res, &evs);
        } else {
            cheat_terms(&mut res, &mod_evs);
        }
    }
    if !shallow && !is_server_plugin && !res.trusted_infra {
        obfuscation(&mut res, &mod_evs);
        client_layout(&mut res, &mod_evs, is_vanilla);
    }
    apply_known_good(&mut res, &trust);

    if depth < MAX_NESTED_DEPTH {
        for ns in &nested {
            if stopped() {
                break;
            }
            let label = format!(
                "{} !/ {}",
                if path_label.is_empty() {
                    display_name
                } else {
                    path_label
                },
                ns.n
            );
            let mut sub = scan_jar_bytes(&path_basename(&ns.n), &ns.b, depth + 1, &label, disk_mode, stop);
            let low = py_lower(&ns.n);
            if sub.rank > 0 && !low.ends_with(".jar") && !low.ends_with(".zip") {
                let ext = path_splitext(&ns.n).1;
                sub.notes.push(format!(
                    "Arşiv '{}' uzantısıyla gizlenmiş{}.",
                    if ext.is_empty() { "uzantısız" } else { ext.as_str() },
                    if ns.why.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", ns.why)
                    }
                ));
            }
            res.nested.push(sub);
        }
        if meta.id.truthy {
            let mut subn: StrList = Vec::new();
            for sub in &res.nested {
                if sub.findings.iter().any(|f| f.key == "handle_closer") {
                    subn.push(sub.name.clone());
                }
            }
            if !subn.is_empty() {
                let s3: StrList = subn.iter().take(3).cloned().collect();
                let mut g: RowGroup = Vec::new();
                for x in &s3 {
                    g.push(rw("hint", "-", &format!("gömülü araç: {}", x)));
                }
                addf(
                    &mut res,
                    "handle_closer_mod",
                    "Mod içinde gizli 'kendini silme / iz gizleme' aracı",
                    "KESIN_HILE",
                    &format!(
                        "Bu Minecraft modu, içine gömülü bir arşivde ({}) oyunun (javaw) dosya tutamaçlarını kapatıp hile dosyasının oyun açıkken silinmesini \
                         sağlayan bir araç taşıyor. Meşru modlarda bulunmaz; hile istemcilerinin ekran paylaşımı \
                         öncesi iz silme (self-destruct) özelliğidir.",
                        join(&s3, ", ")
                    ),
                    g,
                );
            }
        }
    }

    let conceal = concealment_labels(&res);
    weak_to_notes(&mut res);
    certainty_gate(&mut res, &conceal);
    if verified_plugin {
        let dropped = res.findings.len();
        res.findings.clear();
        res.mixins.clear();
        res.server_plugin = true;
        res.kind = "Sunucu eklentisi (plugin) - içerikten doğrulandı".to_string();
        let mut note = format!(
            "Bu dosya bir SUNUCU EKLENTİSİ olarak kökünden doğrulandı: {} tanımı var, ana sınıf ({}) arşivde mevcut ve sunucu API'sinden türüyor; hiçbir sınıfta istemci / Mixin / agent / mod yükleyici izi, \
             gizli sınıf, şifreli yük veya enjeksiyon yapabilen yerel program yok. Sunucu eklentileri oyuncunun \
             istemcisinde çalışmaz; bu yüzden taramada es geçildi.",
            plugin_desc,
            dotted(&plugin_main)
        );
        if dropped != 0 {
            note.push_str(&format!(
                " (Eklentinin kendi kodunda {} olası eşleşme vardı - anti-cheat eklentileri hile adlarını \
                 ve kontrollerini içerdiği için beklenen durumdur.)",
                dropped
            ));
        }
        res.notes.push(note);
    }
    let mut server_has_client_cheat = false;
    if verified_server {
        for f in &res.findings {
            if f.key == "known_client" || f.key == "client_addon" {
                server_has_client_cheat = true;
                break;
            }
        }
    }
    if verified_server && !res.server_plugin && !server_has_client_cheat {
        let dropped = res.findings.len();
        res.findings.clear();
        res.mixins.clear();
        res.trusted_infra = true;
        res.trust_label = server_label.clone();
        res.kind = server_label.clone();
        let mut note = format!(
            "Bu dosya bir SUNUCU YAZILIMI olarak kökünden doğrulandı ({}). Sunucu platformu/proxy \
             oyuncunun istemcisinde DEĞİL sunucuda çalışır; 'paperclip' başlatıcısının çalışma-anı yama yükleyicisi \
             (getResource + defineClass + gömülü yama blobu) istemci-hile tarayıcısının packed_loader/injector \
             kontrolünü yanlışlıkla tetikliyordu. Arşivde istemci / LWJGL / Mixin / mod-yükleyici izi ve mod tanımı \
             (fabric.mod.json/mods.toml) yok; bu yüzden es geçildi. Ic ice gömülü jar'lar ayrıca taranır.",
            server_id
        );
        if dropped != 0 {
            note.push_str(&format!(" (Platformun kendi kodunda {} olası eşleşme vardı.)", dropped));
        }
        res.notes.push(note);
    }
    if qp_agent {
        let modrinth = replace_all(&agent.cls, ".", "/").starts_with("com/modrinth/");
        let lbl = if modrinth {
            "Modrinth App başlatıcı ajanı (Quick Play)"
        } else {
            "başlatıcı ajanı (Quick Play)"
        };
        res.notes.push(format!(
            "Bu dosya bir Minecraft BAŞLATICISININ (launcher) oyunu açarken -javaagent ile yüklediği yardımcı ajandır ({}). \
             İçerikten doğrulandı: Premain-Class ajanı; yalnızca net/minecraft/client/Minecraft yapıcısına \
             'açılışta şu sunucuya baglan' (host/port sistem özelliği) kodunu ekliyor; savaş / hareket / görüş / oyuncu \
             sınıflarına hiçbir referansı yok; ağ erişimi yalnızca başlatıcıyla yerel soket; sınıf tanımlama, şifre çözme, \
             komut çalıştırma, yerel kütüphane veya Attach API yok; diğer tüm sınıflar arşive paketlenmiş ASM/Gson \
             kütüphaneleri. Oyuncuya avantaj sağlamaz.",
            lbl
        ));
        if !res.trusted_infra {
            res.trusted_infra = true;
            res.trust_label = lbl.to_string();
        }
    }
    let mut rank = res.rank;
    for f in &res.findings {
        rank = rank.max(category_rank(&f.category));
    }
    for s in &res.nested {
        rank = rank.max(s.rank);
    }
    res.rank = rank;
    res.relevant = raw_mc || meta.id.truthy || rank > 0 || !encrypted_java.is_empty();
    res.verdict = if rank == 0 && res.official_fabric {
        "TEMIZ (resmi Fabric modulu)".to_string()
    } else if rank == 0 && res.trusted_infra {
        format!("TEMIZ ({})", res.trust_label)
    } else if rank == 0 && res.server_plugin {
        "TEMIZ (sunucu eklentisi)".to_string()
    } else {
        verdict_by_rank(rank)
    };
    res
}

pub fn scan_jar(path: &str) -> ScanResult {
    let Some(data) = read_file(path, -1, 0) else {
        let mut r = ScanResult::default();
        r.file = path.to_string();
        r.name = path_basename(path);
        r.has_sha = false;
        r.verdict = "OKUNAMADI".to_string();
        r.notes.push(format!("Dosya okunamadı: {}", path));
        r.error = "okunamadı".to_string();
        return r;
    };
    let mut res = scan_jar_bytes(&path_basename(path), &data, 0, path, false, None);
    if !py_lower(path).ends_with(".jar") {
        res.notes
            .push("Dosya uzantısı .jar değil ama içeriği bir mod arşivi (gizlenmiş olabilir).".to_string());
        add_finding(
            &mut res,
            "renamed_jar",
            "Uzantısı değiştirilmiş mod dosyası",
            "SUPHELI",
            "Mod klasöründe .jar olmayan ama JAR içeriğine sahip dosya.",
            vec![rw("hint", "-", &path_basename(path))],
            "dosya",
        );
        weak_to_notes(&mut res);
    }
    res
}

pub fn candidate_files(root: &str) -> StrList {
    let mut out: StrList = Vec::new();
    walk_files(
        root,
        &mut |p: &str| {
            let low = py_lower(&path_basename(p));
            if low.ends_with(".jar") {
                out.push(p.to_string());
                return;
            }
            let sz = file_size(p);
            match sz {
                Some(s) if s >= 64 => {}
                _ => return,
            }
            match read_file(p, 4, 0) {
                Some(h) if h == b"PK\x03\x04" => {}
                _ => return,
            }
            let Some(all) = read_file(p, -1, 0) else { return };
            let mut names: Vec<String> = Vec::new();
            if !zip_opens(&all, Some(&mut names)) {
                return;
            }
            for n in names.iter().take(5000) {
                if n.ends_with(".class") {
                    out.push(p.to_string());
                    return;
                }
            }
        },
        2000000,
    );
    out.sort();
    out
}

pub fn scan_directory(root: &str, progress: Option<ProgressFn>, threads: i32) -> Vec<ScanResult> {
    scan_files(&candidate_files(root), progress, threads)
}

pub fn scan_files(files: &[String], progress: Option<ProgressFn>, threads: i32) -> Vec<ScanResult> {
    scan_files_cb(files, progress, threads, None)
}

pub type JarFound<'a> = &'a (dyn Fn(usize, &ScanResult) + Sync);

pub fn scan_files_cb(
    files: &[String],
    progress: Option<ProgressFn>,
    threads: i32,
    on_result: Option<JarFound<'_>>,
) -> Vec<ScanResult> {
    let total = files.len() as i32;
    let mut threads = threads;
    if threads <= 0 {
        threads = 1.max(8.min(cpu_count())) as i32;
    }
    let next = AtomicI32::new(0);
    let done = AtomicI32::new(0);
    let mu = Mutex::new(());
    let nthreads = threads.min(1.max(total)) as usize;
    let mut slots: Vec<Option<ScanResult>> = Vec::new();
    slots.resize_with(files.len(), || None);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _t in 0..nthreads {
            let files = &files;
            let next = &next;
            let done = &done;
            let mu = &mu;
            let work = move || -> Vec<(usize, ScanResult)> {
                let mut local: Vec<(usize, ScanResult)> = Vec::new();
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    if i >= total {
                        break;
                    }
                    let f = &files[i as usize];
                    let r = scan_jar(f);
                    if let Some(cb) = on_result {
                        cb(i as usize, &r);
                    }
                    local.push((i as usize, r));
                    let d = done.fetch_add(1, Ordering::SeqCst) + 1;
                    if let Some(pg) = progress {
                        let _lk = mu.lock();
                        pg(d, total, &path_basename(f));
                    }
                }
                local
            };
            if let Ok(h) = std::thread::Builder::new()
                .stack_size(16 << 20)
                .spawn_scoped(scope, work)
            {
                handles.push(h);
            }
        }
        for h in handles {
            if let Ok(v) = h.join() {
                for (i, r) in v {
                    if let Some(s) = slots.get_mut(i) {
                        *s = Some(r);
                    }
                }
            }
        }
    });
    slots.into_iter().map(|s| s.unwrap_or_default()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rank_and_verdict() {
        assert_eq!(category_rank("KESIN_HILE"), 3);
        assert_eq!(category_rank("YASAKLI_ISLEV"), 2);
        assert_eq!(category_rank("SUPHELI"), 1);
        assert_eq!(category_rank("BILGI"), 0);
        assert_eq!(verdict_by_rank(3), "KESIN HILE");
        assert_eq!(verdict_by_rank(2), "YASAKLI ISLEV");
        assert_eq!(verdict_by_rank(1), "SUPHELI");
        assert_eq!(verdict_by_rank(0), "TEMIZ");
        assert_eq!(verdict_by_rank(9), "TEMIZ");
    }

    #[test]
    fn bcontains_works() {
        assert!(bcontains(b"abc", b""));
        assert!(bcontains(b"abcdef", b"cde"));
        assert!(!bcontains(b"ab", b"abc"));
        assert!(!bcontains(b"abcdef", b"xyz"));
    }

    #[test]
    fn words_split() {
        assert_eq!(words_of("KillAura"), vec!["kill", "aura"]);
        assert_eq!(words_of("ABc"), vec!["a", "bc"]);
        assert_eq!(words_of("kill_aura2"), vec!["kill", "aura", "2"]);
    }

    #[test]
    fn has_term_joins() {
        let w = words_of("Kill Aura");
        assert!(has_term(&w, "killaura"));
        assert!(!has_term(&w, "kill aura"));
    }

    #[test]
    fn junk_names() {
        assert!(junk_name("Il1"));
        assert!(!junk_name("a"));
        assert!(!junk_name("Ilx"));
        assert!(junk_name("IlO12"));
    }

    #[test]
    fn inter_and_desc() {
        let mut v = Vec::new();
        inter_tokens("x method_123 field_4a comp_9", |t| v.push(t.to_string()));
        assert_eq!(v, vec!["method_123", "comp_9"]);
        let mut c = Vec::new();
        desc_classes("(Lnet/minecraft/class_1;I)Ljava/lang/String;", |t| {
            c.push(t.to_string())
        });
        assert_eq!(c, vec!["net/minecraft/class_1", "java/lang/String"]);
    }

    #[test]
    fn member_string() {
        let mut o = None;
        let mut n = String::new();
        assert!(parse_member_string(
            "Lnet/minecraft/class_636;method_2896(I)V",
            &mut o,
            &mut n
        ));
        assert_eq!(o.as_deref(), Some("net/minecraft/class_636"));
        assert_eq!(n, "method_2896");
        assert!(!parse_member_string("*", &mut o, &mut n));
    }

    #[test]
    fn crlf_helpers() {
        assert_eq!(rstrip_crlf(b"ab\r\n\r\n"), b"ab");
        assert_eq!(crlf_to_lf(b"a\r\nb\rc\r\n"), b"a\nb\rc\n");
    }

    #[test]
    fn der_rejects_garbage() {
        assert!(!is_der_crypto_blob(b"hello world 0123456789"));
        assert!(!is_der_crypto_blob(&[0u8; 8]));
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[7u8; 100]), 0.0);
        let all: Vec<u8> = (0..=255u8).collect();
        assert!((shannon_entropy(&all) - 8.0).abs() < 1e-9);
    }

    fn gf(key: &str, label: &str, cat: &str, details: &[&str]) -> Finding {
        let mut f = Finding::default();
        f.key = key.to_string();
        f.label = label.to_string();
        f.category = cat.to_string();
        let mut u = Unit::default();
        u.groups.push(details.iter().map(|d| rw("hint", "a/B", d)).collect());
        f.units.push(u);
        f
    }

    fn gate(fs: Vec<Finding>, conceal: &[&str]) -> ScanResult {
        let mut r = ScanResult::default();
        r.findings = fs;
        let c: StrList = conceal.iter().map(|s| s.to_string()).collect();
        certainty_gate(&mut r, &c);
        r
    }

    #[test]
    fn gate_single_behavior_is_not_certain() {
        let r = gate(vec![gf("reach", "Reach", "KESIN_HILE", &[])], &[]);
        assert_eq!(r.findings[0].category, "SUPHELI");
        let r = gate(
            vec![
                gf("reach", "Reach", "KESIN_HILE", &[]),
                gf("velocity", "Velocity", "KESIN_HILE", &[]),
            ],
            &[],
        );
        assert!(r.findings.iter().all(|f| f.category == "SUPHELI"));
        let r = gate(vec![gf("java_agent", "Java agent", "KESIN_HILE", &[])], &[]);
        assert_eq!(r.findings[0].category, "SUPHELI");
    }

    #[test]
    fn gate_behavior_with_second_evidence_stays_certain() {
        let r = gate(
            vec![gf("killaura", "KillAura", "KESIN_HILE", &[])],
            &["Karartılmış kod"],
        );
        assert_eq!(r.findings[0].category, "KESIN_HILE");
        let r = gate(
            vec![
                gf("reach", "Reach", "KESIN_HILE", &[]),
                gf(
                    "cheat_terms",
                    "Hile terimleri",
                    "KESIN_HILE",
                    &["'killaura' (kod içindeki metin)"],
                ),
            ],
            &[],
        );
        assert!(r.findings.iter().all(|f| f.category == "KESIN_HILE"));
    }

    #[test]
    fn gate_proof_stays_certain() {
        let r = gate(vec![gf("known_client", "Wurst", "KESIN_HILE", &[])], &[]);
        assert_eq!(r.findings[0].category, "KESIN_HILE");
        let r = gate(
            vec![gf(
                "java_agent",
                "Çalışan oyuna sonradan yüklenen gizli Java agent",
                "KESIN_HILE",
                &[],
            )],
            &[],
        );
        assert_eq!(r.findings[0].category, "KESIN_HILE");
        let two = [
            "'killaura' (sınıf/metot/alan adı)",
            "'triggerbot' (sınıf/metot/alan adı)",
        ];
        let r = gate(vec![gf("cheat_terms", "Hile terimleri", "KESIN_HILE", &two)], &[]);
        assert_eq!(r.findings[0].category, "KESIN_HILE");
    }

    #[test]
    fn gate_weak_terms_alone_not_certain() {
        let one = ["'killaura' (sınıf/metot/alan adı)", "'killaura' (kod içindeki metin)"];
        let r = gate(vec![gf("cheat_terms", "Hile terimleri", "KESIN_HILE", &one)], &[]);
        assert_eq!(r.findings[0].category, "SUPHELI");
        let r = gate(
            vec![gf(
                "cheat_terms",
                "Hile terimleri",
                "KESIN_HILE",
                &["'aimbot' (kod içindeki metin)"],
            )],
            &["Karartılmış kod"],
        );
        assert_eq!(r.findings[0].category, "SUPHELI");
        let r = gate(vec![gf("autoclicker", "AutoClicker", "YASAKLI_ISLEV", &[])], &[]);
        assert_eq!(r.findings[0].category, "YASAKLI_ISLEV");
    }
}
