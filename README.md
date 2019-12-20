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

PHP 5.6以上(PHP7.3, 5.6で検証した。それ以下は未検証)。64bitを推奨、ZIP64を使わないなら32bitでも動作する。
また、ファイル名のエンコードに mbstring 関数を利用している。

## 使い方

### 例1. 一時ファイルを作成せずに出力(Downloadさせる)

`Zip::add_file()` でファイルを追加し、`Zip::byte()` でファイルサイズを計測し、`Zip::save()` で出力する

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
$zip->save('php://stdout');
```

圧縮してもDataDescriptorを利用すれば、すぐさまダウンロード開始される。
上と違いContentLengthをセットしていない。圧縮する場合は `Zip::byte()` 実行時に圧縮処理で遅くなるため。

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
$zip->save('php://stdout');
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

## 設定項目

```php
<?php

$zip = new Rezipe\Zip();
# 圧縮するかどうかのBool値
$zip->compress = false;

# 拡張フィールドに精度の高いNTFS時刻(64bit Mtime,Atime,Ctime)を追加する
$zip->ntfsdate = true;

# 拡張フィールドにUnixTime(32bit Mtime,Atime,Ctime)を追加する
$zip->extime   = false;

# 拡張フィールドにUnix情報(Atime,Mtime,Uid,Gid)を追加する(※未検証)
$zip->unixextra = false;

# 拡張フィールドにUnix情報(Uid,Gid)を追加する(※未検証)
$zip->unixextra2 = false;

# LocalFileHeader直後にDataDescriptorを付け加える
$zip->datadesc = false;

# DataDescriptorにsignature("PK\007\008")を付けるかどうか
$zip->datadesc_signature = false;

# デバッグ出力する
$zip->debug = true;

# ZIPファイル内エンコーディングをUTF-8にする
$zip->is_utf8 = true;

# ZIPファイル内エンコーディングを変更したい場合、文字セット名を指定する
#  カンマ区切りで2つ指定すると、
#  'UTF-8', 'CP932', 'Macjapanese', ... (cite: https://www.php.net/manual/ja/mbstring.supported-encodings.php)
$zip->encoding = 'UTF-8,CP932';

# 暗号化(ZipCrypto)ZIPを利用する場合、パスワードを指定する
$zip->zipcrypto = null;

```

