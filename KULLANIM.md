# JournalScanner Kullanım Kılavuzu

Bu kılavuz, bilgisayarlardan pek anlamayan biri için yazıldı. Baştan sona okumanız 10 dakikanızı alır; sonunda programı rahatça kullanabilirsiniz.

---

## 1. JournalScanner nedir?

JournalScanner, bir bilgisayarda **Minecraft hilesi olup olmadığını** kontrol eden bir programdır.

Hile dosyaları genelde adını değiştirerek ya da başka dosyaların içine saklanarak gizlenir. JournalScanner dosyaların **adına değil, içine** bakar. Yani `hile.jar` dosyasının adı `ödev.txt` yapılmış olsa bile içeriğinden tanır.

Program **sadece okur**. Hiçbir dosyayı silmez, değiştirmez, internete bir şey göndermez.

---

## 2. Programı indirmek

1. [Releases](../../releases) sayfasını açın.
2. En üstteki sürümde **`JournalScanner.exe`** dosyasına tıklayıp indirin.

Kurulum yoktur. İndirdiğiniz tek dosya programın kendisidir.

### İndirdiğim dosya gerçekten doğru dosya mı?

Release sayfasında her sürümün altında bir **SHA-256** kodu ve bir **VirusTotal** bağlantısı vardır.

- **SHA-256**, dosyanın parmak izi gibidir. Dosyanın bir harfi bile değişse bu kod tamamen değişir. Kontrol etmek isterseniz, dosyanın bulunduğu klasörde boş bir yere Shift + sağ tık yapıp "PowerShell penceresini burada açın" seçin ve şunu yazın:

  ```
  Get-FileHash JournalScanner.exe
  ```

  Çıkan kod, Release sayfasındaki kodla aynıysa dosya doğrudur.

- **VirusTotal** bağlantısı, dosyanın 70'ten fazla antivirüs programıyla taranmış sonucunu gösterir.

---

## 3. Programı açmak

1. `JournalScanner.exe` dosyasına **sağ tıklayın**.
2. **"Yönetici olarak çalıştır"** seçin.
3. "Bu uygulamanın cihazınızda değişiklik yapmasına izin vermek istiyor musunuz?" sorusuna **Evet** deyin.

**Neden yönetici izni?** Çalışan programların belleğine, Windows'un olay kayıtlarına ve diskin tamamına bakabilmek için gerekir. İzin vermezseniz program yine açılır ama bazı taramalar eksik kalır; sol alttaki sarı **"Yönetici izni yok"** yazısı bunu hatırlatır.

**"Windows bilgisayarınızı korudu" uyarısı çıkarsa:** Bu, programın yeni olduğu ve dijital imzası olmadığı içindir. **"Ek bilgi"** yazısına, sonra **"Yine de çalıştır"** düğmesine tıklayın.

---

## 4. Ekranı tanıyalım

- **Sol menü:** Tarama türleri. Her birinin yanında küçük bir durum etiketi vardır: taranmadı, taranıyor, temiz ya da kaç bulgu çıktığı.
- **Üst şerit:** Genel karar ve toplam sayılar (Toplam, Kesin, Yasaklı, Şüpheli, Temiz).
- **Orta alan:** Seçtiğiniz taramanın sonuç listesi.
- **Alt panel (Kanıt / Ayrıntı):** Listeden bir satıra tıkladığınızda o dosyanın neden işaretlendiğini burada okursunuz.
- **En alt şerit:** O an ne yapıldığı ve ilerleme çubuğu.

---

## 5. Tarama yapmak

Program açılınca **kendiliğinden tarama başlatmaz**. İki seçeneğiniz var:

### Her şeyi taramak (önerilen)

Sol alttaki **"Tüm taramaları başlat"** düğmesine basın. Bütün taramalar aynı anda başlar.

### Sadece bir şeyi taramak

Sol menüden bir kategori seçin (örneğin **Mod Taraması**) ve sayfanın üstündeki **"Tara"** düğmesine basın. Sadece o kategori taranır. Daha önce taradıysanız düğme **"Yeniden tara"** olur.

### İpuçları

- **Oyun açıkken tarayın.** Aktif Client, DLL ve String Scanner taramaları çalışan oyuna bakar. Oyun kapalıysa bu taramalar bir şey bulamaz.
- **Sonuçlar bekletmez.** Bir şey bulunduğu anda listede görünür; taramanın bitmesini beklemeniz gerekmez.
- **Disk taraması uzun sürebilir.** Diskteki her dosyanın içine baktığı için, dosya sayısına göre birkaç dakikadan yarım saate kadar sürebilir. Ekranda kaç dosya tarandığı ve **tahmini kalan süre** yazar. İsterseniz **"Durdur"** ile kesebilirsiniz. Daha kısa bir tarama için **"Hızlı (kullanıcı klasörleri)"** seçeneğini kullanın.

---

## 6. Kararlar ne anlama geliyor?

| Karar | Renk | Anlamı |
|---|---|---|
| **Kesin hile** | Kırmızı | Dosyanın hile olduğu kanıtlandı: bilinen bir hile programının kodu, hile modül adları, oyuna kod sokan yükleyici ya da en az iki bağımsız kanıt bir arada (örneğin hile davranışı + kod gizleme). |
| **Yasaklı işlev** | Turuncu | Tam bir hile istemcisi değil ama sunucuda yasak bir özellik içeriyor (örneğin otomatik tıklama). |
| **Şüpheli** | Sarı | Kesin değil. Elle bakmak gerekir. |
| **Temiz** | Yeşil | Sorun bulunmadı. |
| **Bilgi** | Gri | Hile kararı değil, sadece bilgi (örneğin takılı bir USB cihazı). |

**Önemli:** "Şüpheli" bir sonuç, tek başına birinin hile kullandığı anlamına gelmez. Alt paneldeki açıklamayı okuyup karar verin.

**Kesinlik kuralı:** Program, bir dosya hakkında emin olmadan "Kesin hile" demez. Menzil, geri tepme, otomatik vuruş gibi hile davranışları meşru modlarda da görülebilir (ölçek, savaş, görüntü modları). Bu yüzden böyle bir davranış tek başına bulunursa sonuç **Şüpheli** olur; "Kesin hile" için aynı dosyada ikinci, bağımsız bir kanıt gerekir.

**Açıklamaları okumak:** Her dosyanın en üstünde **Özet** satırı kararı tek cümlede anlatır. Her bulgunun altında önce **Kısaca** (herkesin anlayacağı açıklama), sonra **Ne yapıyor** (teknik ayrıntı) ve kodun neresinde bulunduğu yazar.

---

## 7. Her tarama ne yapar?

- **Mod Taraması:** Minecraft'ın `mods` klasörlerindeki dosyaları inceler. Prism, MultiMC, CurseForge, Modrinth, Lunar, Feather, Badlion gibi başlatıcıların klasörlerini kendisi bulur.
- **Disk Taraması:** Bütün diskte gizlenmiş hile dosyası arar. Adı değiştirilmiş, arşivin (zip, rar, 7z...) içine konmuş ya da başka bir dosyanın içine gömülmüş olsa da bulur.
- **Log Taraması:** Minecraft'ın son günlerdeki kayıt dosyalarına bakar. Hangi modlarla oynandığını oradan çıkarır.
- **Aktif Client:** Şu an çalışan Minecraft'ı inceler: hangi sürüm, hangi başlatıcı, hangi dosyaları kullanıyor, içine bir şey enjekte edilmiş mi.
- **Bluetooth / USB:** Bilgisayara takılmış cihazların listesi (bilgi amaçlı).
- **Prefetch:** Windows, çalıştırılan programların kaydını tutar. Yakın zamanda çalıştırılıp sonra silinmiş hile programlarını buradan yakalar.
- **Olay Görüntüleyicisi:** Windows kayıtlarında, izleri silmek için yapılan işlemleri arar.
- **DLL / Yerel Modül:** Oyunun içine sonradan yüklenmiş hile dosyalarını (DLL) arar.
- **String Scanner:** Oyunun belleğinde kalan hile izlerini arar. Sohbette yazılan hile isimleri sayılmaz, sadece hilenin kendisinden kalan izler sayılır.
- **Tarayıcı Geçmişi:** İnternetten indirilen dosyaları kontrol eder. **Şifrelerinize ve çerezlerinize dokunmaz.**
- **Journal Geçmişi:** Windows'un dosya değişiklik kaydına bakar. Yakın zamanda silinen ya da adı değiştirilen hile dosyalarını yakalar.

---

## 8. Sonuçları incelemek

- **Bir satıra tıklayın:** Alt panelde ayrıntısı çıkar. "Kopyala" ile metni kopyalayabilirsiniz.
- **Çift tıklayın:** Dosyanın bulunduğu klasör açılır.
- **Arama kutusu:** Listede ad, karar ya da yol ile arama yapar.
- **Renkli düğmeler (Kesin, Yasaklı, Şüpheli, Temiz):** Kapattığınız renk listeden gizlenir. Örneğin sadece kırmızıları görmek için diğerlerini kapatın.

---

## 9. Raporu kaydetmek

Sol alttaki **"Raporu kaydet"** düğmesine basın ve kaydedeceğiniz yeri seçin. Dosya türünü de seçebilirsiniz:

- **HTML (varsayılan):** Tarayıcıda açılan, renkli ve düzenli bir rapor. Birine göndermek için en uygunu.
- **CSV:** Excel'de tablo olarak açılır.
- **JSON:** Başka programlar için.
- **TXT:** Düz metin.

---

## 10. Sık sorulan sorular

**Antivirüsüm uyarı veriyor, virüs mü?**
Hayır. Program, hilelerin yaptığına benzer şeyler yapar: diğer programların belleğine bakar, diski tarar. Bazı antivirüsler bu yüzden "şüpheli" diyebilir. Release sayfasındaki VirusTotal bağlantısından sonucu kendiniz görebilirsiniz.

**Dosyalarımı siler mi, değiştirir mi?**
Hayır. Program sadece okur.

**Bilgilerimi bir yere gönderiyor mu?**
Hayır. İnternet bağlantısı kullanmaz. Rapor yalnızca siz kaydederseniz oluşur.

**Tarama ne kadar sürer?**
Disk taraması hariç her şey genelde bir iki dakikada biter. Disk taraması dosya sayısına bağlıdır; ekranda tahmini süre yazar.

**Program kapandı ya da dondu, ne yapmalıyım?**
Programın yanında (ya da `%TEMP%` klasöründe) **`JournalScanner_hata_raporu.txt`** adında bir dosya oluşur. Bu dosyayı geliştiriciye gönderin. İçinde kişisel bilgi yoktur, sadece hatanın nerede olduğu yazar.
