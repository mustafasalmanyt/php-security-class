# PHP Güvenlik Sınıfı

Web uygulamaları için kapsamlı güvenlik önlemleri sağlayan PHP kütüphanesi. SQL injection, XSS saldırıları, rate limiting ve veri şifreleme özelliklerini içerir.

## ✨ Özellikler

- **Rate Limiting**: IP tabanlı istek sınırlama
- **Process Limiting**: Tekrar eden işlemleri önleme (spam koruması)
- **Veri Şifreleme/Çözme**: AES-128-ECB ile güvenli şifreleme
- **SQL Injection Koruması**: Kapsamlı SQL temizleme
- **XSS Koruması**: HTML tag ve script temizleme
- **Veri Temizleme**: Çeşitli veri türleri için temizlik araçları
- **Random ID Üretimi**: Güvenli rastgele kimlik oluşturma
- **Şifre Hashleme**: Güçlendirilmiş MD5 hashleme
- **Geçici Dosya Yönetimi**: Kullanıcı verilerini geçici saklama

## 🚀 Kurulum

1. Güvenlik sınıfını projenize dahil edin:
```php
require_once 'security.class.php';
```

2. Log sistemini dahil edin (Zorunlu):
```php
require_once 'log.class.php'; // GitHub profilimde bulabilirsiniz
```

3. Güvenlik kontrolü tanımlayın:
```php
<?php
define("index", true); // Güvenlik için gerekli
?>
```

4. Sınıfı kullanmaya başlayın:
```php
$security = new security();
```

## 📖 Kullanım

### Rate Limiting (İstek Sınırlama)

#### IP Tabanlı İstek Sınırlama
```php
$user = [
    'ip' => $_SERVER['REMOTE_ADDR']
];

// 60 saniye içinde 10'dan fazla istek yapılmasını engelle
if ($security->limitIpQueries($user, 10, 60)) {
    die("Çok fazla istek! Lütfen bekleyin.");
}

// Normal işlemler devam edebilir
echo "İşlem başarılı!";
```

#### Process Limiting (İşlem Sınırlama)
```php
$user = [
    'ip' => $_SERVER['REMOTE_ADDR']
];

// Aynı email ile 120 saniye içinde tekrar mail göndermeyi engelle
$email = "user@example.com";
if ($security->processLimit($user, 120, $email, 'email_send')) {
    die("Bu email adresine zaten mail gönderildi. Lütfen bekleyin.");
}

// Mail gönderme işlemi
sendEmail($email);
```

### Veri Şifreleme ve Çözme

#### Veri Şifreleme
```php
$sensitiveData = "Kredi kartı numarası: 1234-5678-9012-3456";
$encrypted = $security->encryptData($sensitiveData);
echo "Şifrelenmiş: " . $encrypted;
```

#### Veri Çözme
```php
$encryptedData = "abc123def456..."; // Şifrelenmiş veri
$decrypted = $security->decryptData($encryptedData);
echo "Çözülmüş: " . $decrypted;
```

### Veri Temizleme ve Güvenlik

#### Kapsamlı Veri Kontrolü
```php
$userInput = "<script>alert('XSS')</script>SELECT * FROM users;";
$cleanData = $security->control($userInput, true);
echo $cleanData; // Güvenli, temizlenmiş veri
```

#### SQL Injection Koruması
```php
$maliciousInput = "'; DROP TABLE users; --";
$cleanSql = $security->cleanSqlQuery($maliciousInput);
echo $cleanSql; // SQL komutları temizlenmiş
```

#### XSS Koruması
```php
$htmlInput = "<script>alert('hack')</script><b>Normal metin</b>";
$cleanHtml = $security->CleanHtmlTag($htmlInput);
echo $cleanHtml; // Sadece güvenli içerik
```

### Özel Temizleme İşlemleri

#### Sadece Sayıları Temizleme
```php
$mixed = "abc123def456";
$onlyLetters = $security->cleanNumber($mixed);
echo $onlyLetters; // "abcdef"
```

#### Sadece Harfleri Temizleme
```php
$mixed = "abc123def456";
$onlyNumbers = $security->cleanString($mixed);
echo $onlyNumbers; // "123456"
```

#### Özel Karakterleri Temizleme
```php
$text = "Merhaba! @#$ Dünya? 123";
$clean = $security->cleanCharacter($text, "!?"); // ! ve ? karakterlerine izin ver
echo $clean; // "Merhaba! Dünya? 123"
```

#### Boşlukları Düzenleme
```php
$text = "Çok    fazla     boşluk    var";
$clean = $security->replaceSpace($text);
echo $clean; // "Çok fazla boşluk var"
```

### Random ID ve Şifre İşlemleri

#### Rastgele ID Üretimi
```php
// Karma (harf+sayı) 10 karakter
$randomId = $security->generateRandomId(10);
echo $randomId; // "aB3xY9mK2P"

// Sadece sayı 6 karakter
$numberCode = $security->generateRandomId(6, 'number');
echo $numberCode; // "847293"

// Sadece harf 8 karakter
$stringCode = $security->generateRandomId(8, 'string');
echo $stringCode; // "KmNpQrSt"

// Özel karakterlerle
$customCode = $security->generateRandomId(10, 'number', '!@#');
echo $customCode; // "123!@#456!"
```

#### Güçlendirilmiş Şifre Hashleme
```php
$password = "kullanici123";
$hashedPassword = $security->md5Pass($password);
echo $hashedPassword; // Güçlendirilmiş MD5 hash
```

## 🔧 API Referansı

### Rate Limiting Metodları

| Method | Parametreler | Açıklama | Dönüş |
|--------|-------------|----------|-------|
| `limitIpQueries($user, $limit, $seconds)` | user array, limit int, seconds int | IP tabanlı istek sınırlama | bool |
| `processLimit($user, $seconds, $value, $objName)` | user array, seconds int, value mixed, objName string | İşlem tekrarını önleme | bool |

### Şifreleme Metodları

| Method | Parametreler | Açıklama | Dönüş |
|--------|-------------|----------|-------|
| `encryptData($data)` | data string | Veriyi şifreler | string |
| `decryptData($data)` | data string | Şifreyi çözer | string |
| `md5Pass($password)` | password string | Güçlendirilmiş şifre hash | string |

### Temizleme Metodları

| Method | Parametreler | Açıklama | Dönüş |
|--------|-------------|----------|-------|
| `control($value, $type, $excludeCharacters)` | value string, type bool, excludeCharacters string | Kapsamlı veri temizleme | string |
| `cleanSqlQuery($value)` | value string | SQL injection temizleme | string |
| `CleanHtmlTag($value)` | value string | XSS ve HTML temizleme | string |
| `cleanNumber($value)` | value string | Sayıları temizler | string |
| `cleanString($value)` | value string | Harfleri temizler | string |
| `cleanCharacter($value, $excludeCharacters)` | value string, excludeCharacters string | Özel karakter temizleme | string |
| `replaceSpace($string)` | string string | Boşluk düzenleme | string |

### Yardımcı Metodları

| Method | Parametreler | Açıklama | Dönüş |
|--------|-------------|----------|-------|
| `generateRandomId($length, $type, $character)` | length int, type string, character string | Rastgele ID üretimi | string |

## 🛡️ Güvenlik Özellikleri

### SQL Injection Koruması
- 30+ farklı SQL komut pattern'ini tespit eder
- UNION, SELECT, DROP, INSERT vb. komutları neutralize eder
- Prepared statement kullanımını destekler

### XSS Koruması
- `<script>` ve `<style>` etiketlerini tamamen kaldırır
- HTML special karakterleri encode eder
- Güvenli HTML etiketlerine izin verebilir

### Rate Limiting
- IP tabanlı istek sınırlama
- Geçici dosya sisteminde kullanıcı takibi
- Esnek zaman ve limit ayarları

### Veri Şifreleme
- AES-128-ECB algoritması
- Günlük tabanlı anahtar rotasyonu
- URL-safe karakter dönüşümü

## 📁 Dosya Yapısı

```
/proje-klasoru/
├── security.class.php
├── log.class.php
├── tmp/
│   ├── tmp_[ip_hash1]
│   ├── tmp_[ip_hash2]
│   └── ...
└── index.php
```

### Geçici Dosya Formatı
```json
{
    "user": {
        "ip": "192.168.1.1",
        "userAgent": "Mozilla/5.0..."
    },
    "limitIpQueries": {
        "query_count": 5,
        "last_query_time": 1686123456
    },
    "processLimit_email_send": {
        "time": 1686123456,
        "value": "user@example.com"
    }
}
```

## ⚠️ Gereksinimler

- PHP 7.0 veya üzeri
- OpenSSL extension (şifreleme için)
- **Log sistemi**: `log.class.php` dosyası (GitHub profilimde bulabilirsiniz)
- Dosya yazma izinleri (/tmp klasörü için)
- mbstring extension (Unicode desteği için)

## 💡 Kullanım Senaryoları

### Web Sitesi Güvenliği
```php
// Form verilerini güvenli hale getirme
$name = $security->control($_POST['name'], true);
$email = $security->control($_POST['email']);
$message = $security->control($_POST['message'], true, ".,!?");
```

### API Rate Limiting
```php
$user = ['ip' => $_SERVER['REMOTE_ADDR']];

// API endpoint için rate limiting
if ($security->limitIpQueries($user, 100, 3600)) { // Saatte 100 istek
    http_response_code(429);
    die(json_encode(['error' => 'Rate limit exceeded']));
}
```

### E-ticaret Güvenliği
```php
// Kredi kartı bilgilerini şifreleme
$cardNumber = $security->encryptData($_POST['card_number']);
$cvv = $security->encryptData($_POST['cvv']);

// Veritabanına güvenli kayıt
$db->Insert("INSERT INTO payments (card_encrypted, cvv_encrypted) VALUES (?, ?)", 
           [$cardNumber, $cvv]);
```

### Kullanıcı Kaydı
```php
// Spam kaydını önleme
$user = ['ip' => $_SERVER['REMOTE_ADDR']];
$email = $_POST['email'];

if ($security->processLimit($user, 300, $email, 'registration')) {
    die("Bu email ile yakın zamanda kayıt yapıldı.");
}

// Güvenli şifre hash
$password = $security->md5Pass($_POST['password']);
```

## 🔗 İlgili Projeler

Bu güvenlik sistemi şu projelerimde kullanılmaktadır:
- [PHP Database Kütüphanesi](https://github.com/mustafasalmanyt/php-pdo-database) - Veritabanı güvenliği için
- [PHP Log Sistemi](https://github.com/mustafasalmanyt/php-log-system) - Hata loglaması için

## 👨‍💻 Geliştirici

**Mustafa Salman YT**
- Website: [mustafa.slmn.tr](https://mustafa.slmn.tr)
- Email: mustafa@slmn.tr


## 📝 Lisans

Bu proje MIT lisansı altında yayınlanmıştır.


## ⭐ Önemli Notlar

- Üretim ortamında `encryptDataKey` değerini mutlaka değiştirin
- Geçici dosyalar düzenli olarak temizlenmelidir
- Rate limiting değerlerini ihtiyacınıza göre ayarlayın
- Log dosyalarını düzenli kontrol edin

## 🙏 Teşekkürler

PHP güvenlik topluluğuna ve açık kaynak geliştiricilere teşekkürler.
