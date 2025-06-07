<?php

!defined("index") ? die("Geçersiz İstek :(") : null;
date_default_timezone_set('Europe/Istanbul');

class security
{

    private $encryptDataKey = '!_AekcX02--';
    private $encryptDataCipher = 'AES-128-ECB';
    private $log;
    private $tmpFilePath = '/tmp/';

    private function tmpHandleFile(array $user = [])
    {
        $tmpFolder = __DIR__ . $this->tmpFilePath;
        $fileName = 'tmp_' . md5($user['ip']);
        $filePath = __DIR__ . $this->tmpFilePath . $fileName;
        // Dizin kontrolü ve oluşturma
        if (!file_exists($tmpFolder)) {
            mkdir($tmpFolder, 0777, true);
        }
        // Dosya kontrolü ve işlemler
        if (!file_exists($filePath)) {
            // Dosya yoksa oluştur ve içine IP'yi JSON formatında ekle
            $fileContent = @file_get_contents($filePath);
            $fileContentJson = @json_decode($fileContent, true);
            $fileContentJson['user'] = $user;
            $user['user']['userAgent'] = $_SERVER['HTTP_USER_AGENT'];
            file_put_contents($filePath, json_encode($fileContentJson, JSON_PRETTY_PRINT));
        }
        return $fileName;
    }

    public function limitIpQueries($user, $limit, $seconds = 60)
    {
        // $seconds saniye içerisinde istek $limit aşarsa $seconds saniye boyunca ture dondurur
        $tmpHandleFile = __DIR__ . $this->tmpFilePath . $this->tmpHandleFile($user);
        $fileContent = @file_get_contents($tmpHandleFile);
        $fileContentJson = @json_decode($fileContent, true);
        $currentTime = time();
        if (!isset($fileContentJson['limitIpQueries'])) {
            $fileContentJson['limitIpQueries'] = [
                'query_count' => 0,
                'last_query_time' => $currentTime
            ];
        }

        $lastQueryTime = $fileContentJson['limitIpQueries']['last_query_time'];
        $queryCount = $fileContentJson['limitIpQueries']['query_count'];
        $recentQueryCount = 0;

        if (($currentTime - $lastQueryTime) < $seconds) {
            $recentQueryCount = $queryCount;
        }
        if ($recentQueryCount >= $limit) {
            // İşleme izin verilmedi
            return true;
        }
        $fileContentJson['limitIpQueries']['last_query_time'] = time();
        $fileContentJson['limitIpQueries']['query_count'] = $recentQueryCount + 1;
        file_put_contents($tmpHandleFile, json_encode($fileContentJson, JSON_PRETTY_PRINT));
        // İşleme izin verildi
        return false;
    }

    public function processLimit($user, $seconds = 120, $value = null, $objName = null)
    {
        // birkez izin verilir ve $value aynı olduğu süre $seconds saniye boyunca izin verilmez // mail gönderimi için kullandım
        $tmpHandleFile = __DIR__ . $this->tmpFilePath . $this->tmpHandleFile($user);
        $fileContent = file_get_contents($tmpHandleFile);
        $fileContentJson = json_decode($fileContent, true);

        // Kontrol et: Eğer dosya içeriğinde 'processLimit' anahtarı bulunuyorsa
        if (isset($fileContentJson['processLimit_' . $objName])) {
            // Eğer $value eşitse ve $seconds süresi bitmemişse
            if ($value === $fileContentJson['processLimit_' . $objName]['value'] && (time() - $fileContentJson['processLimit_' . $objName]['time']) < $seconds) {
                // İşleme izin verilmedi
                return true;
            }
        }

        // Yeni değerleri ayarla veya varsa güncelle
        $fileContentJson['processLimit_' . $objName] = [
            'time' => time(),
            'value' => $value
        ];

        // Dosyayı güncelle
        file_put_contents($tmpHandleFile, json_encode($fileContentJson, JSON_PRETTY_PRINT));

        // İşleme izin verildi
        return false;
    }

    public function generateRandomId($length = 10, $type = null, $character = '')
    {
        if ($type == 'number') {
            $characters = '0123456789' . $character;
        } elseif ($type == 'string') {
            $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' . $character;
        } else {
            $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' . $character;
        }
        $charactersLength = strlen($characters);
        $randomUniqueId = '';
        for ($i = 0; $i < $length; $i++) {
            $randomUniqueId .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomUniqueId;
    }
    public function md5Pass($password)
    {
        $passValue = substr($this->encryptDataKey, 0, 2) . $password . substr($this->encryptDataKey, -3);
        return md5($passValue);
    }


    public function encryptData($data = 0)
    {
        try {
            $cipher = $this->encryptDataCipher;
            $key = date('Ymd') . $this->encryptDataKey;
            $value = trim(openssl_encrypt(@$data, $cipher, $key));
            $value = str_replace("/", "_", $value);
            $encoded = str_replace("+", "-", $value);
            return $encoded;
        } catch (PDOException $e) {
            $this->ExceptionLog($e->getMessage());
            die();
        }
    }
    public function decryptData($data)
    {
        try {
            $value = str_replace("_", "/", $data);
            $value = str_replace("-", "+", $value);
            $cipher = $this->encryptDataCipher;
            $key = date('Ymd') . $this->encryptDataKey;
            $decoded = trim(openssl_decrypt($value, $cipher, $key));
            return $decoded;
        } catch (PDOException $e) {
            $this->ExceptionLog($e->getMessage());
            die();
        }
    }

    public function replaceSpace($string)
    {
        $string = preg_replace("/\s+/", " ", $string);
        $string = trim($string);
        return $string;
    }
    public function cleanNumber($value)
    {
        return preg_replace('/\d+/i', '', $value);
    }
    public function cleanString($value)
    {
        return preg_replace('/[a-zA-Z]+/i', '', $value);
    }
    public function cleanCharacter($value, $excludeCharacters = '')
    {
        $data = mb_convert_encoding($value, 'UTF-8', 'UTF-8');
        $excludeCharactersPattern = preg_quote($excludeCharacters, '/');
        $data = preg_replace('/[^\w\s' . $excludeCharactersPattern . ']+/u', '', $data);

        return $data;
    }
    public function cleanSqlQuery($value)
    {
        $clean = trim($value);

        // Kötü niyetli SQL komutlarını etkisiz hale getirmek için regex desenleri
        $patterns = [
            // SQL komutları
            '/\bselect\b/i',
            '/\binsert\b/i',
            '/\bupdate\b/i',
            '/\bdelete\b/i',
            '/\bdrop\b/i',
            '/\bunion\b/i',
            '/\bexec\b/i',
            '/\bcall\b/i',
            '/\bcreate\b/i',
            '/\balter\b/i',
            '/\btruncate\b/i',
            '/\bdrop\b/i',
            '/\bgrant\b/i',
            '/\brevoke\b/i',
            '/\bshow\b/i',
            '/\bdesc\b/i',
            '/\btable\b/i',
            '/\bview\b/i',
            '/\bwhere\b/i',
            '/\blike\b/i',
            '/\bgroup by\b/i',
            '/\border by\b/i',
            '/\blimit\b/i',
            '/\bjoin\b/i',
            '/\binner\b/i',
            '/\bouter\b/i',
            '/\bleft\b/i',
            '/\bright\b/i',
            '/\bcast\b/i',
            '/\bconvert\b/i',
            '/\bselect\b/i',
            '/\bunion\b/i',
            // SQL enjeksiyon teknikleri
            '/\bselect\s+.*\bfrom\b/i',  // select ... from
            '/\bselect\s+.*\bwhere\b/i', // select ... where
            '/\bunion\s+all\b/i',        // union all
            '/\bunion\s+select\b/i',     // union select
            '/\bselect\s+.*\bunion\b/i', // select ... union
            '/\bselect\s+.*\blimit\b/i', // select ... limit
            '/\bselect\s+.*\border\s+by\b/i', // select ... order by
            '/\bupdate\s+set\b/i',       // update set
            '/\binsert\s+into\b/i',      // insert into
            '/\bdelete\s+from\b/i',      // delete from
            '/\bdrop\s+table\b/i',      // drop table
            '/\bcreate\s+table\b/i',    // create table
            '/\balter\s+table\b/i',     // alter table

            // İki ve tek tırnak karakterlerini kaçırma
            '/\b\'/i',
            '/\b\"/i'
        ];

        foreach ($patterns as $pattern) {
            $clean = preg_replace($pattern, '', $clean);
        }

        // Kaçış karakterleri ekle
        $clean = addslashes($clean);

        return $clean;
    }

    public function CleanHtmlTag($value)
    {
        $value = trim($value);
        // <script> ve <style> etiketlerini kaldırın
        $value = preg_replace('/<script\b[^>]*>.*?<\/script>/is', '', $value);
        $value = preg_replace('/<style\b[^>]*>.*?<\/style>/is', '', $value);

        // Diğer HTML etiketlerini temizleyin (strip_tags sadece izin verilen etiketleri saklamanıza izin verir)
        $value = strip_tags($value);

        $value = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');

        return $value;
    }

    public function control($value, $type = false, $excludeCharacters = "")
    {
        if ($value != NULL) {
            $data = trim($value);
            if ($type === true) {
                $data = $this->replaceSpace($data);
                $data = $this->cleanCharacter($data, $excludeCharacters);
            }
            $data = $this->cleanSqlQuery($data);
            $data = $this->CleanHtmlTag($data);
            return $data;
        } else {
            return NULL;
        }
    }

    private function ExceptionLog($message, $sql = "")
    {
        $exception = 'İşlenmeyen özel durum. <br />';
        $exception .= $message;
        $exception .= "<br /> Hatayı günlükte bulabilirsin.";

        if (!empty($sql)) {
            $message .= "\r\nRaw SQL : " . $sql;
        }
        $this->log->write($message);

        return $exception;
    }
}
