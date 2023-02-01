# Rezipe

## 概要

PHPによるZIPエンコーダ。以下の特徴がある

* 一時ファイルを作成せずに出力可能
* 出力サイズを計測可能(ContenLengthとして使える)
* 大きなファイルを扱っても省メモリ
* 暗号化も可能
* ZIP64(ファイルサイズ4GB以上など)にも対応
* 詳細な更新日/作成日を設定可能
* PHP5.6以上、32bit版でも動作。ただしZIP64には64bit版が必要

## 動作環境

PHP 5.6以上(PHP8.2, 7.3, 5.6で検証した。それ以下は未検証)。64bitを推奨、ZIP64を使わないなら32bitでも動作する。AES暗号化機能を使う場合は openssl 関数が必要。

## 使い方

### 例1. 一時ファイルを作成せずに出力(Downloadさせる)

`Zip::add_file()` でファイルを追加し、`Zip::bytes()` でファイルサイズを計測し、`Zip::save()` で出力する

```php
<?php
require_once 'rezipe.php';
$zip = new Rezipe\Zip();
$zip->compress = false;  # 無圧縮
$zip->is_utf8 = true;
foreach(glob('path/to/dir/*.jpg') as $file) {
	$zip->add_file($file);
}
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename=download.zip');
header('Content-Length: ' . $zip->bytes());
$zip->save('php://output');
```

圧縮してもDataDescriptorを利用すれば、すぐさまダウンロード開始される。
上と違いContentLengthをセットしていない。圧縮する場合は `Zip::bytes()` 実行時に圧縮処理で遅くなるため。

```php
<?php
require_once 'rezipe.php';
$zip = new Rezipe\Zip();
$zip->compress = true;  # Deflate圧縮
$zip->datadesc = true;  # DataDescriptorを利用
$zip->is_utf8 = true;
foreach(glob('path/to/dir/*.jpg') as $file) {
	$zip->add_file($file);
}
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename=download.zip');
$zip->save('php://output');
```

### 例2. ローカルに保存

`Zip::save()` にファイルパスを指定すればローカルに保存される

```php
<?php
require_once 'rezipe.php';
$zip = new Rezipe\Zip();
$zip->compress = true;
$zip->add_data("test data\nzipzipzip", 'test.txt');
$zip->save('saveTo/foo.zip');
```

### 例3. 暗号化

※昔ながらの脆弱な暗号化なので注意
※DataDescriptorと併用してはいけない

```php
<?php
require_once 'rezipe.php';
$zip = new Rezipe\Zip();
$zip->compress = true;
$zip->zipcrypto = 'p4$5w0rd';
$zip->add_file("secret.pdf");
$zip->add_file("otakara.jpg");
$zip->add_file("passwords.txt");
$zip->save('crypted.zip');
```

### 例4. AES暗号化

より強力な暗号化方式だが、展開できるアーカイバを選ぶ(Windows/Mac標準では開けない。7-zipでは開ける)。
こちらはDataDescriptorと併用可能なので、圧縮しつつ即ダウンロードできる

```php
<?php
require_once 'rezipe.php';
$zip = new Rezipe\Zip();
$zip->compress = true;
$zip->aescrypto = 'verylongstrongpassword';
$zip->datadesc = true;
$zip->add_file("secret.pdf");
$zip->add_file("otakara.jpg");
$zip->add_file("passwords.txt");
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename=aes_crypted.zip');
$zip->save('php://output');
```

### 例5. ファイル名としてShift-JISを使う場合

Windows7以前の標準アーカイバでは、ZIP内ファイル名のエンコーディングがShift-JISでないと文字化けしていた。あえてそのようなzipファイルを作りたい場合は以下のようにすれば良い。文字コード変換にmbstring拡張が必要。

```php
<?php
require_once 'rezipe.php';
$zip = new Rezipe\Zip();
$zip->is_utf8 = false;  # UTF-8フラグはOFFにしておく
$zip->add_file("元ファイル名(UTF-8).txt",
        mb_convert_encoding("変換後ファイル名(SJIS).txt", "CP932", "UTF-8"));
$zip->save('for_old_windows.zip');
```


## 設定項目

```php
<?php

$zip = new Rezipe\Zip();
# 圧縮するかどうかのBool値
$zip->compress = false;

# 拡張フィールドに精度の高いNTFS時刻(64bit Mtime,Atime,Ctime)を追加する
$zip->ntfsdate = false;

# 拡張フィールドにUnixTime(32bit Mtime,Atime,Ctime)を追加する
$zip->extime   = false;

# 拡張フィールドにUnix情報(Atime,Mtime,Uid,Gid)を追加する(※未検証)
$zip->unixextra = false;

# 拡張フィールドにUnix情報(Uid,Gid)を追加する(※未検証)
$zip->unixextra2 = false;

# 拡張フィールドにUnicodePathを追加する
$zip->upath = false;

# LocalFileHeader直後にDataDescriptorを付け加える
$zip->datadesc = false;

# DataDescriptorにsignature("PK\007\008")を付けるかどうか(MacOSX向けにはtrueを推奨)
$zip->datadesc_signature = false;

# ZIPファイル内エンコーディングをにUTF-8を指定する
$zip->is_utf8 = false;

# 暗号化(ZipCrypto)ZIPを利用する場合、パスワードを指定する
$zip->zipcrypto = null;

# AES暗号化(WinZipのAES-256暗号)ZIPを利用する場合、パスワードを指定する
$zip->aescrypto = null;

```

