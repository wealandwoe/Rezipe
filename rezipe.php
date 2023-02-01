<?php
namespace Rezipe;

const VERSION = '0.9.3';
const FE_SIGNATURE = 0x04034b50; # "PK\x03\x04"
const DD_SIGNATURE = 0x08074b50; # "PK\x07\x08"
const CD_SIGNATURE = 0x02014b50; # "PK\x01\x02"
const EOCD_SIGNATURE = 0x06054b50; # "PK\x05\x06"
const Z64_EOCDR_SIGNATURE = 0x06064b50; # "PK\x06\x06"
const Z64_EOCDL_SIGNATURE = 0x07064b50; # "PK\x06\x07"

class Zip {
	public $files_info;
	public $compress;
	public $ntfsdate;
	public $unixextra;
	public $unixextra2;
	public $extime;
	public $upath;
	public $datadesc;
	public $datadesc_signature;
	public $is_utf8;
	public $zipcrypto;
	public $aescrypto;
	
	function __construct($callback = false) {
		$this->files_info = array();
		$this->compress = false;
		$this->ntfsdate = false;
		$this->unixextra = false;
		$this->unixextra2 = false;
		$this->extime = false;
		$this->upath = false;
		$this->datadesc = false;
		$this->datadesc_signature = false;
		$this->is_utf8 = false;
		$this->zipcrypto = null;
		$this->aescrypto = null;
		if ($callback) {$callback($this);}
	}
	
	function add_data($data, $virtual_path, $comp = null) {
		if ($comp === null) {$comp = $this->compress;}
		$ent = new FileEntry($virtual_path, $comp);
		if ($this->is_utf8) {$ent->set_utf8(true);}
		if (is_string($this->zipcrypto)) {$ent->set_zipcrypto($this->zipcrypto);}
		elseif ($this->aescrypto) {$ent->set_aescrypto($this->aescrypto);}
		$ent->set_data($data);
		$this->files_info[] = $ent;
	}
	
	function add_file($path, $virtual_path = null, $comp = null) {
		if ($virtual_path === null) {$virtual_path = basename($path);}
		if ($comp === null) {$comp = $this->compress;}
		$ent = new FileEntry($virtual_path, $comp);
		if ($this->is_utf8) {$ent->set_utf8(true);}
		if (is_string($this->zipcrypto)) {$ent->set_zipcrypto($this->zipcrypto);}
		elseif ($this->aescrypto) {$ent->set_aescrypto($this->aescrypto);}
		$ent->set_file($path);
		$this->files_info[] = $ent;
	}
	
	function bytes($debug = false) {
		$s = 0;
		$stat = array("files" => 0, "cd" => 0, "eocd" => 0, "z64eocd" => 0, "unknown" => 0);
		foreach($this->entries() as $ent) {
			$b = $ent->bytes();
			$type = $ent instanceof CentralDirectory ? 'cd' : (
					$ent instanceof FileEntry ? 'files' : (
					$ent instanceof EndOfCentralDirectory ? 'eocd' : (
					$ent instanceof Zip64EndOfCentralDirectoryRecord ? 'z64eocd' : (
					$ent instanceof Zip64EndOfCentralDirectoryLocator ? 'z64eocd' : 'unknown'
			))));
			$stat[$type] += $b;
			$s += $b;
			if ($debug) {$ent->debug();}
		}
		if ($debug) {echo var_export($stat,true) . "\n";}
		return $s;
	}
	
	function entries() {
		return new ZipEntryIterator($this, $this->files_info);
	}
	
	function save($path) {
		$fh = fopen($path, 'wb');
		foreach($this->entries() as $ent) {
			$ent->writeto($fh);
		}
		fclose($fh);
	}
}

class ZipEntryIterator implements \Iterator {
	private $entries;
	private $file_entries;
	private $offset;
	private $position;
	private $zip;
	private $eocd_position;
	
	function __construct($zip, $file_entries) {
		$this->entries = array() + $file_entries;
		$this->file_entries = $file_entries;
		$this->offset = 0;
		$this->position = 0;
		$this->zip = $zip;
		$this->eocd_position = 0;
		$file_entries[0]->offset = 0;
		$cds = array();
		foreach($this->file_entries as $ent) {
			$cd = new CentralDirectory($ent);
			$cds[] = $cd;
			$this->entries[] = $cd;
		}
		$this->eocd_position = count($this->entries);
		$this->entries[] = $eocdr = new Zip64EndOfCentralDirectoryRecord($cds);
		$this->entries[] = new Zip64EndOfCentralDirectoryLocator($eocdr);
		$this->entries[] = new EndOfCentralDirectory($cds);
	}
	
	#[\ReturnTypeWillChange]
	function current() {
		$ent = $this->entries[$this->position];
		$ent->set_offset($this->offset);
		if ($this->zip->datadesc && ($ent instanceof FileEntry)) {
			$ent->use_datadescriptor($this->zip->datadesc_signature);
		}
		$this->set_extra_field($ent);
		return $ent;
	}
	
	#[\ReturnTypeWillChange]
	function key() {
		return $this->position;
	}
	
	#[\ReturnTypeWillChange]
	function next() {
		$this->offset += $this->entries[$this->position++]->bytes();
		if ($this->position < $this->eocd_position) {return;}
		
		### TODO: 本来はEOCDのフィールドのうち、どれか1つでもあふれた場合にZIP64フォーマットになる
		
		# offsetやentry数があふれていたらZip64EOCDを利用し、そうでないならEOCDへジャンプ
		if ($this->position === $this->eocd_position &&
				$this->offset <= 0xffffffff &&
				count($this->file_entries) <= 0xffff) {
			$this->position += 2;
		}
	}
	
	#[\ReturnTypeWillChange]
	function rewind() {
		$this->position = 0;
		$this->offset = 0;
	}
	
	function set_extra_field(&$ent) {
		$cls = get_class($ent);
		if ($cls !== 'Rezipe\FileEntry' && $cls !== 'Rezipe\CentralDirectory') {return $ent;}
		# set Extra Fields (for FileEntry and CentralDirectory)
		$ent->set_extra_field(null, true); //reset
		$file_entry = $ent;
		if ($for_cd = ($cls === 'Rezipe\CentralDirectory')) {
			$file_entry = $ent->file_entry;
		}
		# ZIP64 extended information
		$ent->append_zip64_exdata();

		# NTFS date (CentralDirectory only)
		if ($this->zip->ntfsdate && $for_cd) {
			$ent->set_extra_field(new NTFSExtraField(
					$file_entry->mtime, $file_entry->atime, $file_entry->ctime));
		}
		# Unix Extra Field (FileEntry only)
		if ($this->zip->unixextra) {
			if ($for_cd) {
				$ent->madeby = $ent->madeby | 0x0300; //03:unix + 3F:PKZIP6.3
			} else {
				$ent->set_extra_field(new UnixExtraField(array(
						"atime" => $file_entry->atime,
						"mtime" => $file_entry->mtime)));
			}
		}
		# Unix Extra Field Type 2(Uid,Gid)
		if ($this->zip->unixextra2) {
			if ($for_cd) {
				$ent->madeby = $ent->madeby | 0x0300;
			} else {
				$ent->set_extra_field(new UnixExtraFieldType2(array(
						"cd" => $for_cd)));
			}
		}
		# Extended Timestamp
		if ($this->zip->extime) {
			$ent->set_extra_field(new ExtendedTimestamp(array(
					"flags" => 7, // 0b0111 => 1:Mtime | 2:Atime | 4:Ctime
					"mtime" => $file_entry->mtime,
					"atime" => $file_entry->atime,
					"ctime" => $file_entry->ctime,
					"cd" => $for_cd)));
		}
		# Info-ZIP Unicode Path Extra Field
		if ($this->zip->upath) {
			if ($ent->version < 20) {$ent->version = 20;}
			$ent->set_extra_field(new UnicodePathExtraField(array(
					"path" => $file_entry->filename)));
		}
		# AE-x Encryption Extra Field
		if ($this->zip->aescrypto) {
			if ($ent->version < 51) {$ent->version = 51;}
			$ent->set_extra_field(new AExEncryptionExtraField(array(
					"method" => $file_entry->method)));
		}
	}
	
	#[\ReturnTypeWillChange]
	function valid() {
		return isset($this->entries[$this->position]);
	}
}

interface AbstractEntry {
	public function bytes();
	
	public function set_offset($offset);
	
	public function writeto($io, $blen = null);
}

class FileEntry implements AbstractEntry {
	public $version;
	public $flag;
	public $method;
	public $time;
	public $date;
	public $crc32;
	public $compsize;
	public $size;
	public $len;
	public $exlen;
	public $exdata;
	public $filename;
	public $extra_fields;
	public $mtime;
	public $atime;
	public $ctime;
	public $dddata;
	public $offset;
	public $compress;
	public $datadesc;
	public $datadesc_signature;
	public $is_zip64;
	public $zipcrypto;
	public $aescrypto;
	
	private $path;
	private $data;
	private $is_directory;
	private $is_crc32_ready;
	private $is_compsize_ready;
	
	const DEFAULT_BUFLEN = 1024*1024;
	
	function __construct($virtual_path, $comp = false) {
		$this->path = $this->data = null;
		$this->compress = $comp;
		$this->datadesc = false;
		$this->datadesc_signature = false;
		$this->is_directory = null;
		$this->version = 10;
		$this->flag = 0;
		$this->method = $this->compress ? ($this->compress === true ? 8 : $this->compress) : 0;
		$this->mtime = $this->atime = $this->ctime = time();
		$this->time = null;
		$this->date = null;
		$this->crc32 = null;
		$this->compsize = 0;
		$this->size = 0;
		$this->filename = $virtual_path;
		$this->len = strlen($this->filename);
		$this->extra_fields = array();
		$this->exdata = "";
		$this->exlen = 0;
		$this->offset = 0;
		$this->dddata = "";
		$this->set_time($this->mtime);
		$this->is_crc32_ready = $this->is_compsize_ready = false;
		$this->is_zip64 = false;
		$this->zipcrypto = null;
		$this->aescrypto = null;
	}
	
	function append_zip64_exdata() {
		if ($this->datadesc) {return;}
		if (!$this->is_zip64) {return;}
		if ($this->has_extra_field(Zip64ExtendedInformation::HEADER_ID_ZIP64)) {return;}
		if ($this->version < 45) {$this->version = 45;}
		$this->set_extra_field(new Zip64ExtendedInformation(array(
				"size" => $this->size, "compsize" => $this->get_compsize(), "cd" => false)));
	}
	
	function bytes() {
		if (!$this->is_compsize_ready) {$this->calc_compsize();}
		$this->append_zip64_exdata();
		$ddsize = $this->datadesc ? 12 : 0;
		if ($this->datadesc && $this->datadesc_signature) {$ddsize += 4;}
		if ($this->datadesc && $this->is_zip64) {$ddsize += 8;}
		return $this->header_size() + $this->get_compsize() + $ddsize;
	}
	
	function calc_crc32() {
		if ($this->data) {
			$this->set_crc32(crc32($this->data));
			return $this->crc32;
		}
		$dd = DataConverter::convert(array(
				"path" => $this->path,
				"buffer" => static::DEFAULT_BUFLEN,
				"crc32" => true));
		$this->set_crc32($dd->get_crc32('N'));
		return $this->crc32;
	}
	
	function calc_compsize($blen = null) {
		if (!$blen) {$blen = static::DEFAULT_BUFLEN;}
		if ($this->method === 0) {
			$this->set_compsize($this->size);
			return $this->compsize;
		}
		$b = 0;
		if ($this->data) {
			$b += strlen(gzdeflate($this->data));
		} elseif ($this->size < $blen) {
			// small file
			$b += strlen(gzdeflate(file_get_contents($this->path)));
		} else {
			// large file
			$dd = DataConverter::convert(array(
					"path" => $this->path,
					"buffer" => $blen,
					"zlib" => $this->compress,
					"strlen" => true));
			$b = $dd->get_compsize();
		}
		$this->set_compsize($b);
		return $this->compsize;
	}
	
	function debug() {
		$this->append_zip64_exdata();
		$offset = 0;
		echo "##offset,size,desc,val,binary\n";
		$data = array(
			array(\Rezipe\FE_SIGNATURE, 'V', "file entry signature", "4B"),
			array($this->version, 'v', "version needed extract(minimum)", "2B"),
			array($this->flag, 'v', "general purpose bit flag", "2B"),
			array(is_string($this->aescrypto) ? 99 : $this->method,'v', "compression emthod", "2B"),
			array($this->time, 'v', "last modified time", "2B"),
			array($this->date, 'v', "last modified date", "2B"),
			array($this->datadesc || is_string($this->aescrypto) ? 0 : $this->get_crc32(), 'V', "CRC-32", "4B"),
			array($this->datadesc ? 0 : ($this->is_zip64 ? 0xffffffff : $this->get_compsize()), 'V', "compressed size", "4B"),
			array($this->datadesc ? 0 : ($this->is_zip64 ? 0xffffffff : $this->size), 'V', "uncompressed size", "4B"),
			array($this->len, 'v', "file name length(n)", "2B"),
			array($this->exlen, 'v', "extra field length(m)", "2B"),
			array($this->filename, '', "file name", "nB"),
			array(bin2hex($this->get_exdata()), '', "extra field", "mB")
		);
		if ($this->datadesc) {
			$data[] = array($this->get_dddata(), '', "data descriptor",
					($this->datadesc_signature ? 16 : 12) . "B");
		}
		foreach($data as $arr) {
			list($val, $p, $desc, $size) = $arr;
			$b = $p ? pack($p, $val) : $val;
			echo "{$offset},{$size},{$desc}," . var_export($val,true) . ',' . ($val === $b ? '//' : ('"'.bin2hex($b).'"')) . "\n";
			$offset += $b ? strlen($b) : 0;
		}
	}
	
	function get_compsize($raw_compsize = false) {
		if (!$this->is_compsize_ready) {$this->calc_compsize();}
		if ($raw_compsize) {return $this->compsize;}
		//zipcrypto,aescryptoの場合はcompressed sizeを水増し
		$overhead = 0;
		if (is_string($this->zipcrypto)) {
			$overhead = 12;
		} elseif (is_string($this->aescrypto)) {
			$overhead = 28; //strength[0x03] => 28, [0x02] => 24, [0x01] => 20
		}
		return $this->compsize + $overhead;
	}
	
	function get_crc32() {
		if (!$this->is_crc32_ready) {$this->calc_crc32();}
		return $this->crc32;
	}
	
	function get_dddata() {
		$sig = $this->datadesc_signature ? pack('V', \Rezipe\DD_SIGNATURE) : "";
		$pack_template = $this->is_zip64 ? 'VPP' : 'VVV';
		$crc32 = is_string($this->aescrypto) ? 0 : $this->get_crc32();
		$this->dddata = $sig . pack($pack_template, $crc32, $this->get_compsize(), $this->size);
		return $this->dddata;
	}
	
	function get_exdata() {
		$this->exdata = "";
		foreach($this->extra_fields as $exf) {
			$this->exdata .= $exf->to_s();
		}
		$this->exlen = strlen($this->exdata);
		return $this->exdata;
	}
	
	function get_payload() {
		if ($this->is_directory) {return "";}
		$raw = $this->data ? $this->data : file_get_contents($this->path);
		if ($this->compress) {$raw = gzdeflate($raw);}
		return is_string($this->zipcrypto) ? 
				ZipCrypto::encrypt($raw, $this->zipcrypto, $this->get_crc32()) : (
				is_string($this->aescrypto) ?
				AExCrypto::encrypt($raw, $this->aescrypto) : $raw);
	}
	
	function has_extra_field($header_id) {
		foreach($this->extra_fields as $exf) {
			if ($exf->header_id !== $header_id) {continue;}
			return true;
		}
		return false;
	}
	
	function header() {
		$this->append_zip64_exdata();
		return pack('VvvvvvVVVvv',
				\Rezipe\FE_SIGNATURE,  #4B
				$this->version,       #2B
				$this->flag,          #2B
				is_string($this->aescrypto) ? 99 : $this->method, #2B
				$this->time,          #2B
				$this->date,          #2B
				$this->datadesc || is_string($this->aescrypto) ? 0 : $this->get_crc32(),    #4B
				$this->datadesc ? 0 : ($this->is_zip64 ? 0xffffffff : $this->get_compsize()), #4B
				$this->datadesc ? 0 : ($this->is_zip64 ? 0xffffffff : $this->size),     #4B
				$this->len,           #2B
				$this->exlen) .       #2B
				$this->filename .
				$this->get_exdata();
	}
	
	function header_size() {
		return 30 + $this->len + $this->exlen;
	}
	
	function set_aescrypto($password) {
		$this->aescrypto = $password;
		if (is_string($password)) {
			$this->flag = $this->flag | 1;
		} else {
			$this->flag = $this->flag & ~1;
		}
	}
	
	function set_compsize($compsize) {
		$this->compsize = $compsize;
		$this->is_compsize_ready = true;
		$overhead = is_string($this->zipcrypto) ? 12 : ($this->aescrypto ? 28 : 0);
		if ($compsize+$overhead > 0xffffffff) {$this->is_zip64 = true;}
	}
	
	function set_crc32($crc32) {
		$this->crc32 = $crc32;
		$this->is_crc32_ready = true;
	}
	
	function set_data($data) {
		$this->path = null;
		$this->data = $data;
		$this->is_directory = false;
		$this->mtime = $this->atime = $this->ctime = time();
		$this->set_size(strlen($data));
		$this->set_time($this->mtime);
		if (!$this->compress) {
			$this->set_compsize($this->size);
		}
	}
	
	function set_directory() {
		$this->is_directory = true;
		$this->version = 20;
		$this->mtime = $this->atime = $this->ctime = time();
		$this->set_size(0);
		$this->set_compsize(0);
		$this->set_crc32(0);
		if (!preg_match('|/$|', $this->filename)) {
			$this->filename .= '/';
		}
		$this->set_time($this->mtime);
	}
	
	function set_extra_field($data, $reset = null) {
		if ($reset || !$data) {
			$this->extra_fields = array();
			$this->exlen = 0;
			$this->exdata = "";
		}
		if (!$data) {return;}
		$this->extra_fields[] = $data;
		$this->exdata = "";
		$this->exlen = 0;
		foreach($this->extra_fields as $exf) {
			$this->exlen += $exf->bytes();
		}
	}
	
	function set_file($filepath) {
		$this->path = $filepath;
		$this->is_directory = is_dir($filepath);
		if ($this->is_directory || $this->compress && $this->version < 20) {$this->version = 20;}
		$this->mtime = filemtime($filepath);
		$this->atime = fileatime($filepath);
		$this->ctime = filectime($filepath);
		if ($this->is_directory) {
			if (!preg_match('|/$|', $this->filename)) {
				$this->filename .= '/';
			}
			$this->set_size(0);
			$this->set_compsize(0);
			$this->set_crc32(0);
		} else {
			$this->set_size(filesize($filepath));
			$this->set_time($this->mtime);
			if (!$this->compress) {
				$this->set_compsize($this->size);
			}
		}
	}
	
	function set_offset($offset) {
		$this->offset = $offset;
	}
	
	function set_size($size) {
		$this->size = $size;
		if ($size > 0xffffffff) {$this->is_zip64 = true;}
	}
	
	# File modification time 	0x7d1c = 0111110100011100
	# hour = (01111)10100011100 = 15
	# minute = 01111(101000)11100 = 40
	# second = 01111101000(11100) = 28 = 56 seconds
	# 15:40:56
	# File modification date 	0x354b = 0011010101001011
	# year = (0011010)101001011 = 26
	# month = 0011010(1010)01011 = 10
	# day = 00110101010(01011) = 11
	# 10/11/2006 
	function set_time($time = null) {
		if (!$time) {$time = $this->mtime;}
		$this->mtime = $time;
		list($y,$m,$d,$h,$i,$s) = explode('/', date('Y/m/d/H/i/s', $time));
		$this->date = ($y - 1980) << 9 | ($m - 0) << 5 | ($d - 0);
		$this->time = (($h - 0) << 11) | ($i - 0) << 5 | ceil(($s-0)/2.0);
	}
	
	function set_utf8($is_utf8) {
		if ($is_utf8) {
			$this->flag = $this->flag | (1 << 11);
		} else {
			$this->flag = $this->flag & ~(1 << 11);
		}
	}
	
	function set_zipcrypto($password) {
		$this->zipcrypto = $password;
		if (is_string($password)) {
			$this->flag = $this->flag | 1;
		} else {
			$this->flag = $this->flag & ~1;
		}
	}
	
	function to_s($blen = null) {
		if (!$blen) {$blen = static::DEFAULT_BUFLEN;}
		return $this->header() . 
				$this->get_payload() . 
				($this->datadesc ? $this->get_dddata() : "");
	}
	
	function use_datadescriptor($signature = null) {
		if (!$signature) {$signature = $this->datadesc_signature;}
		$this->datadesc = true;
		$this->datadesc_signature = $signature;
		$this->flag = $this->flag | 8;
		if ($this->is_crc32_ready && $this->is_compsize_ready) {$this->get_dddata();}
	}
	
	function writeto($io, $blen = null) {
		if (!$blen) {$blen = static::DEFAULT_BUFLEN;}
		if ($this->size < $blen) {
			fwrite($io, $this->to_s($blen));
			return;
		}
		fwrite($io, $this->header());
		if ($this->is_directory) {return;}
		$this->writetofile($io, $blen);
		fwrite($io, ($this->datadesc ? $this->get_dddata() : ""));
	}
	
	function writetofile($io, $blen) {
		$crc32 = !$this->is_crc32_ready;
		if (is_string($this->zipcrypto)) {
			// zipcrypto には CRC-32 の値を使うので、先に処理する必要がある
			$crc32 = $this->get_crc32();
		}
		$dd = DataConverter::convert(array(
				"path" => $this->path,
				"data" => $this->data ? $this->data : null,
				"transfer" => $io,
				"buffer" => $blen,
				"zlib" => $this->compress,
				"strlen" => !$this->is_compsize_ready,
				"crc32" => $crc32,
				"zipcrypto" => $this->zipcrypto,
				"aescrypto" => $this->aescrypto));
		if (!$this->is_compsize_ready) {
			// overhead込みサイズなので調整
			$overhead = is_string($this->zipcrypto) ? 12 : (
					is_string($this->aescrypto) ? 28 : 0);
			$this->set_compsize($dd->get_compsize() - $overhead);
		}
		if (!$this->is_crc32_ready) {
			$this->set_crc32($dd->get_crc32('N'));
		}
	}
}

class CentralDirectory implements AbstractEntry {
	public $file_entry;
	public $madeby;
	public $version;
	public $exlen;
	public $exdata;
	public $extra_fields;
	public $commlen;
	public $comm;
	public $diskstart;
	public $inattr;
	public $exattr;
	public $offset;
	public $is_zip64;

	function __construct($file_entry) {
		$this->file_entry = $file_entry;
		$this->madeby = 0x003F;  # 00: DOS(FAT), 3F: 63 -> '6.3' -> 'PKZIP v6.3'
		$this->version = $this->file_entry->version;
		$this->comm = "";
		$this->commlen = 0;
		$this->diskstart = 0;
		$this->inattr = 0;
		$this->exattr = 0;
		$this->offset = 0;
		$this->extra_fields = array();
		$this->exdata = "";
		$this->exlen = 0;
		$this->is_zip64 = $this->file_entry->is_zip64;
	}
	
	function append_zip64_exdata() {
		if (!$this->is_zip64) {return;}
		if ($this->has_extra_field(Zip64ExtendedInformation::HEADER_ID_ZIP64)) {return;}
		$this->version = 45;
		$this->set_extra_field(new Zip64ExtendedInformation(array(
				"size" => $this->file_entry->size,
				"compsize" => $this->file_entry->get_compsize(),
				"offset" => $this->file_entry->offset,
				"diskstart" => $this->diskstart,
				"cd" => true)));
	}
	
	function bytes() {
		return 46 + $this->file_entry->len + $this->exlen + $this->commlen;
	}
	
	function debug() {
		$offset = 0;
		echo "##offset,size,desc,val,binary\n";
		$data = array(
			array(\Rezipe\CD_SIGNATURE, 'V', "cd signature", "4B"),
			array($this->madeby, 'v', "version made by", "2B"),
			array($this->version, 'v', "version needed extract(minimum)", "2B"),
			array($this->file_entry->flag, 'v', "general purpose bit flag", "2B"),
			array(is_string($this->file_entry->aescrypto) ? 99 : $this->file_entry->method,'v', "compression emthod", "2B"),
			array($this->file_entry->time, 'v', "last modified time", "2B"),
			array($this->file_entry->date, 'v', "last modified date", "2B"),
			array(is_string($this->file_entry->aescrypto) ? 0 : $this->file_entry->get_crc32(), 'V', "CRC-32", "4B"),
			array($this->file_entry->get_compsize() > 0xffffffff ? 0xffffffff : $this->file_entry->get_compsize(),
					'V', "compressed size", "4B"),
			array($this->file_entry->size > 0xffffffff ? 0xffffffff : $this->file_entry->size,
					'V', "uncompressed size", "4B"),
			array($this->file_entry->len, 'v', "file name length(n)", "2B"),
			array($this->exlen, 'v', "extra field length(m)", "2B"),
			array($this->commlen, 'v', "file comment length(k)", "2B"),
			array($this->diskstart > 0xffff ? 0xffff : $this->diskstart, 'v', "disk where cd starts", "2B"),
			array($this->inattr, 'v', "internal file attributes", "2B"),
			array($this->exattr, 'V', "external file attributes", "4B"),
			array($this->file_entry->offset > 0xffffffff ? 0xffffffff : $this->file_entry->offset,
					'V', "offset of local file header", "4B"),
			array($this->file_entry->filename, '', "file name", "nB"),
			array(bin2hex($this->get_exdata()), '', "extra field", "mB"),
			array($this->comm, '', "comment", "kB")
		);
		foreach($data as $arr) {
			list($val, $p, $desc, $size) = $arr;
			$b = $p ? pack($p, $val) : $val;
			echo "{$offset},{$size},{$desc}," . var_export($val,true) . ',' . ($val === $b ? '//' : ('"'.bin2hex($b).'"')) . "\n";
			$offset += $b ? strlen($b) : 0;
		}
	}
	
	function get_exdata() {
		$this->exdata = "";
		foreach($this->extra_fields as $exf) {
			$this->exdata .= $exf->to_s();
		}
		$this->exlen = strlen($this->exdata);
		return $this->exdata;
	}
	
	function has_extra_field($header_id) {
		foreach($this->extra_fields as $exf) {
			if ($exf->header_id !== $header_id) {continue;}
			return true;
		}
		return false;
	}
	
	function set_comment($comm) {
		$this->comm = $comm;
		$this->commlen = strlen($comm);
	}
	
	function set_extra_field($data, $reset = null) {
		if ($reset || !$data) {
			$this->extra_fields = array();
			$this->exlen = 0;
			$this->exdata = "";
		}
		if (!$data) {return;}
		$this->extra_fields[] = $data;
		$this->exdata = "";
		$this->exlen = 0;
		foreach($this->extra_fields as $exf) {
			$this->exlen += $exf->bytes();
		}
	}
	
	function set_offset($offset) {
		$this->offset = $offset;
		if ($offset > 0xffffffff) {$this->is_zip64 = true;}
	}
	
	function to_s($blen = null) {
		return pack('VvvvvvvVVVvvvvvVV',
				\Rezipe\CD_SIGNATURE, #4B
				$this->madeby,
				$this->version,
				$this->file_entry->flag,
				is_string($this->file_entry->aescrypto) ? 99 : $this->file_entry->method,
				$this->file_entry->time,
				$this->file_entry->date,
				is_string($this->file_entry->aescrypto) ? 0 : $this->file_entry->get_crc32(),    #4B
				$this->file_entry->get_compsize() > 0xffffffff ? 0xffffffff : $this->file_entry->get_compsize(), #4B
				$this->file_entry->size > 0xffffffff ? 0xffffffff : $this->file_entry->size,     #4B
				$this->file_entry->len,
				$this->exlen,
				$this->commlen,
				$this->diskstart > 0xffff ? 0xffff : $this->diskstart,
				$this->inattr,
				$this->exattr,   #4B
				$this->file_entry->offset > 0xffffffff ? 0xffffffff : $this->file_entry->offset) . #4B
				$this->file_entry->filename .
				$this->get_exdata() .
				$this->comm;
	}
	
	function writeto($io, $blen = null) {
		fwrite($io, $this->to_s());
	}
}

class EndOfCentralDirectory implements AbstractEntry {
	public $central_directories;
	public $disknum;
	public $diskstart;
	public $diskcdtotal;
	public $cdtotal;
	public $cdsize;
	public $commlen;
	public $comm;
	public $offset;
	
	function __construct($cds) {
		$this->central_directories = $cds;
		$this->disknum = 0;
		$this->diskstart = 0;
		$this->diskcdtotal = $this->cdtotal = count($cds);
		$this->cdsize = 0;
		$this->commlen = 0;
		$this->comm = "";
	}
	
	function bytes() {
		return 22 + $this->commlen;
	}
	
	function debug() {
		$this->update();
		$offset = 0;
		echo "##offset,size,desc,val,binary\n";
		$cd0 = $this->central_directories[0];
		$data = array(
			array(\Rezipe\EOCD_SIGNATURE, 'V', "eocd signature", "4B"),
			array($this->disknum > 0xffff ? 0xffff : $this->disknum, 'v', "number of the disk", "2B"),
			array($this->diskstart > 0xffff ? 0xffff : $this->diskstart, 'v', "disk where cd starts", "2B"),
			array($this->diskcdtotal > 0xffff ? 0xffff : $this->diskcdtotal, 'v', "number of cd on the disk", "2B"),
			array($this->cdtotal > 0xffff ? 0xffff : $this->cdtotal, 'v', "total number of cd", "2B"),
			array($this->cdsize > 0xffffffff ? 0xffffffff : $this->cdsize, 'V', "size of cd(bytes)", "4B"),
			array($cd0->offset > 0xffffffff ? 0xffffffff : $cd0->offset, 'V', "offset of start of cd", "4B"),
			array($this->commlen, '', "comment length (n)", "2B"),
			array($this->comm, '', "comment", "nB")
		);
		foreach($data as $arr) {
			list($val, $p, $desc, $size) = $arr;
			$b = $p ? pack($p, $val) : $val;
			echo "{$offset},{$size},{$desc}," . var_export($val,true) . ',' . ($val === $b ? '//' : ('"'.bin2hex($b).'"')) . "\n";
			$offset += $b ? strlen($b) : 0;
		}
	}
	
	function set_comment($comm) {
		$this->comm = $comm;
		$this->commlen = strlen($comm);
	}
	
	function set_offset($offset) {
		$this->offset = $offset;
	}
	
	function to_s() {
		$this->update();
		$cd0 = $this->central_directories[0];
		return pack('VvvvvVVv',
				\Rezipe\EOCD_SIGNATURE, #4B
				$this->disknum > 0xffff ? 0xffff : $this->disknum,         #2B
				$this->diskstart > 0xffff ? 0xffff : $this->diskstart,
				$this->diskcdtotal > 0xffff ? 0xffff : $this->diskcdtotal,
				$this->cdtotal > 0xffff ? 0xffff : $this->cdtotal,
				$this->cdsize > 0xffffffff ? 0xffffffff : $this->cdsize,         #4B
				$cd0->offset > 0xffffffff ? 0xffffffff : $cd0->offset,
				$this->commlen) .       #2B
				$this->comm;
	}
	
	function update() {
		$this->cdsize = 0;
		foreach($this->central_directories as $cd) {
			$this->cdsize += $cd->bytes();
		}
	}
	
	function writeto($io, $blne = null) {
		fwrite($io, $this->to_s());
	}
}

# ZIP64 end of central directory record
#   56Byte+?(sig:4, size:8, madeby:2, version:2, disknum:4, diskstart:4, diskcdtotal:8, cdtotal:8, cdsize:8, offset:8, exdata:?)
class Zip64EndOfCentralDirectoryRecord implements AbstractEntry {
	public $central_directories;
	public $offset;
	public $size;
	public $madeby;
	public $version;
	public $disknum;
	public $diskstart;
	public $diskcdtotal;
	public $cdtotal;
	public $cdsize;
	public $exdata;
	public $exlen;
	
	function __construct($cds) {
		$this->central_directories = $cds;
		$this->size = 44;
		$this->madeby = $this->version = 45;
		$this->disknum = 0;
		$this->diskstart = 0;
		$this->diskcdtotal = $this->cdtotal = count($cds);
		$this->cdsize = 0;
		$this->exdata = "";
		$this->exlen = 0;
	}
	
	function bytes() {
		return 12 + $this->size + $this->exlen;
	}
	
	function debug() {
		$this->update();
		$offset = 0;
		echo "##offset,size,desc,val,binary\n";
		$data = array(
			array(\Rezipe\Z64_EOCDR_SIGNATURE, 'V', "zip64 eocd record signature", "4B"),
			array($this->size, 'P', "size of zip64 eocd record", "8B"),
			array($this->madeby, 'v', "", "2B"),
			array($this->version, 'v', "", "2B"),
			array($this->disknum, 'V', "number of the disk", "4B"),
			array($this->diskstart, 'V', "number of the disk with the start of the cd", "4B"),
			array($this->diskcdtotal, 'P', "total number of entries in the cd on this disk", "8B"),
			array($this->cdtotal, 'P', "total number of entries in the cd", "8B"),
			array($this->cdsize, 'P', "size of the cd", "8B"),
			array($this->central_directories[0]->offset, 'P', "offset of start of cd with respect to the starting disk number", "8B"),
			array($this->exdata, '', "zip64 extensible data sector", "nB")
		);
		foreach($data as $arr) {
			list($val, $p, $desc, $size) = $arr;
			$b = $p ? pack($p, $val) : $val;
			echo "{$offset},{$size},{$desc}," . var_export($val,true) . ',' . ($val === $b ? '//' : ('"'.bin2hex($b).'"')) . "\n";
			$offset += $b ? strlen($b) : 0;
		}
	}
	
	function set_offset($offset) {
		$this->offset = $offset;
	}
	
	function to_s() {
		$this->update();
		return pack('VPvvVVPPPP',
				\Rezipe\Z64_EOCDR_SIGNATURE, #4B
				$this->size,                 #8B
				$this->madeby,               #2B
				$this->version,
				$this->disknum,              #4B
				$this->diskstart,
				$this->diskcdtotal,          #8B
				$this->cdtotal,
				$this->cdsize,
				$this->central_directories[0]->offset) .
				$this->exdata;
	}
	
	function update() {
		$this->cdsize = 0;
		foreach($this->central_directories as $cd) {
			$this->cdsize += $cd->bytes();
		}
	}
	
	function writeto($io, $blen = null) {
		fwrite($io, $this->to_s());
	}
}

# ZIP64 end of central directory locator
#   20Byte(sig:4, diskstart:4, z64eocdr_offset:8, disktotal:4)
class Zip64EndOfCentralDirectoryLocator implements AbstractEntry {
	public $z64eocdr;
	public $offset;
	public $diskstart;
	public $disktotal;
	
	function __construct($z64eocdr) {
		$this->z64eocdr = $z64eocdr;
		$this->diskstart = 0;
		$this->disktotal = 1;
	}
	
	function bytes() {
		return 20;
	}
	
	function debug() {
		$offset = 0;
		echo "##offset,size,desc,val,binary\n";
		$data = array(
			array(\Rezipe\Z64_EOCDL_SIGNATURE, 'V', "zip64 eocd locator signature", "4B"),
			array($this->diskstart, 'V', "number of the disk with the start of the zip64 eocd", "4B"),
			array($this->z64eocdr->offset, 'P', "relative offset of the zip64 eocd record", "8B"),
			array($this->disktotal, 'V', "total number of disks", "4B")
		);
		foreach($data as $arr) {
			list($val, $p, $desc, $size) = $arr;
			$b = $p ? pack($p, $val) : $val;
			echo "{$offset},{$size},{$desc}," . var_export($val,true) . ',' . ($val === $b ? '//' : ('"'.bin2hex($b).'"')) . "\n";
			$offset += $b ? strlen($b) : 0;
		}
	}
	
	function set_offset($offset) {
		$this->offset = $offset;
	}
	
	function to_s() {
		return pack('VVPV',
				\Rezipe\Z64_EOCDL_SIGNATURE, #4B
				$this->diskstart,            #4B
				$this->z64eocdr->offset,     #8B
				$this->disktotal);           #4B
	}
	
	function writeto($io, $blen = null) {
		fwrite($io, $this->to_s());
	}
}

class ZipCrypto {
	public static $crc_table;
	public $key0;
	public $key1;
	public $key1_h;
	public $key1_l;
	public $key2;
	private $func;
	private $entry_crc;
	private $encryption_header;

	function __construct() {
		$this->key0 = 305419896;
		$this->key1 = 591751049;
		$this->key2 = 878082192;
		$this->func = array(
			"update_keys" => "update_keys" . (PHP_INT_SIZE === 4 ? '_int4' : '_int8')
		);
		if (PHP_INT_SIZE === 4) {
			$this->key1_l = $this->key1 & 0xffff;
			$this->key1_h = ($this->key1 >> 16) & 0xffff;
		}
		if (!isset(static::$crc_table)) {
			static::make_crc_table();
		}
	}
	
	function decrypt_byte() {
		$temp = ($this->key2 | 2) & 0xffff;
		return (($temp * ($temp ^ 1)) >> 8) & 0xff;
	}
	
	function decrypt_header($buffer) {
		$len = strlen($buffer);
		if ($len !== 12) {throw new Exception('Invalid buffer. expects 12 bytes but ' . $len);}
		$this->set_encryption_header($buffer);
		return $this->update($buffer, false);
	}
	
	function get_crc32() {
		return $this->entry_crc;
	}
	
	function has_encryption_header() {
		return isset($this->encryption_header);
	}
	
	function set_crc32($crc32) {
		$this->entry_crc = $crc32;
	}
	
	function set_encryption_header($hdr) {
		$this->encryption_header = $hdr;
	}
	
	function set_password($password) {
		$len = strlen($password);
		for($i = 0; $i < $len; $i++) {
			$this->update_keys(ord($password[$i]));
		}
	}
	
	function random_header() {
		return static::randbytes(11) . chr(($this->entry_crc >> 24) & 0xff);
	}
	
	function update($buffer, $enc = false) {
		$len = strlen($buffer);
		$out_buffer = "";
		for($i = 0; $i < $len; $i++) {
			$c = ord($buffer[$i]);
			$d = $this->decrypt_byte();
			if (!$enc) {$c = $c ^ $d;}
			$this->update_keys($c);
			if ($enc) {$c = $c ^ $d;}
			$out_buffer .= chr($c);
		}
		return $out_buffer;
	}
	
	function update_keys($char) {
		return call_user_func(array($this, $this->func['update_keys']), $char);
	}
	
	function update_keys_int4($char) {
		$this->key0 = static::crc_update($this->key0, $char);
		# [key1 = key1 + (key0 & 0xff)]
		$h = $this->key1_h;
		$l = $this->key1_l + ($this->key0 & 0xff);
		if ($l > 0xffff) {
			$h = ($h + ($l >> 16)) & 0xffff;
			$l &= 0xffff;
		}
		# [key1 = key1 * 134775813 + 1]
		#    key1      == (key1_h << 16) + key1_l
		#    134775813 == (2056 << 16) + 33797
		#   とすると
		#    key1 * 134775813 + 1
		#     -> ((key1_h<<16)+key1_l) * ((2056<<16)+33797) + 1
		#     -> (key1_h*2056)<<32 + ((key1_h*33797)<<16) + ((key1_l*2056)<<16) + key1_l*33797 + 1
		#    32bit以上は無視出来るので
		#     -> ((key1_h*33797+key1_l*2056)<<16) + key1_l*33797 + 1
		$h = $h * 33797 + 2056 * $l;
		$l = $l * 33797 + 1;
		if ($l > 0xffff) {
			$h = ($h + ($l >> 16)) & 0xffff;
			$l &= 0xffff;
		}
		$this->key1_h = $h;
		$this->key1_l = $l;
		$this->key1 = ($h << 16) | $l;
		$this->key2 = static::crc_update($this->key2, $this->key1_h >> 8);
	}
	
	function update_keys_int8($char) {
		$this->key0 = static::crc_update($this->key0, $char);
		$this->key1 = ($this->key1 + ($this->key0 & 0xff)) & 0xffffffff;
		$this->key1 = ($this->key1 * 134775813 + 1) & 0xffffffff;
		$this->key2 = static::crc_update($this->key2, $this->key1 >> 24);
	}
	
	static function crc32($crc, $buf) {
		$crc ^= 0xffffffff;
		$len = strlen($buf);
		for ($i = 0; $i < $len; $i++) {
			$crc = static::crc_update($crc, ord($buf[$i]));
		}
		return $crc ^ 0xffffffff;
	}
	
	static function crc_update($crc, $char) {
		return static::$crc_table[($crc ^ $char) & 0xff] ^ ($crc >> 8) & 0x00ffffff;
	}
	
	static function decrypt($data, $password, $crc32) {
		$zc = new ZipCrypto();
		$zc->set_password($password);
		$zc->set_crc32($crc32);
		$enc_hdr = $zc->decrypt_header(substr($data, 0, 12));
		if (is_int($crc32) && ((($crc32 >> 24) & 0xff) !== ord($enc_hdr[11]))) {
			return false;
		}
		return $zc->update(substr($data, 12), false);
	}
	
	static function encrypt($data, $password, $crc32) {
		$zc = new ZipCrypto();
		$zc->set_password($password);
		$zc->set_crc32($crc32);
		$enc_hdr = $zc->update($zc->random_header(), true);
		$zc->set_encryption_header($enc_hdr);
		return $enc_hdr . $zc->update($data, true);
	}
	
	static function make_crc_table() {
		$table = array();
		for ($i = 0; $i < 256; $i++) {
			$c = $i;
			for ($j = 0; $j < 8; $j++) {
				$c = ($c & 1) ? (0xEDB88320 ^ ($c >> 1) & 0x7fffffff) : (($c >> 1) & 0x7fffffff);
			}
			$table[] = $c;
		}
		static::$crc_table = $table;
	}
	
	static function randbytes($len) {
		$out = '';
		$prng = function_exists('openssl_random_pseudo_bytes') ? 'openssl_random_pseudo_bytes' : (
				function_exists('random_bytes') ? 'random_bytes' : ('mt_rand'));
		if ($prng === 'mt_rand') {
			for($i=0; $i<$len; $i++) {$out .= chr(mt_rand(0, 255));}
		} else {
			$out = $prng($len);
		}
		return $out;
	}
}

/**
 * AEx Encryption
 */
class AExCrypto {
	const MODE_DECRYPT = 0;
	const MODE_ENCRYPT = 1;
	public $version;
	public $strength;
	public $mode;
	public $updated;
	public $finalized;
	private $salt;
	private $dk;
	private $hmac;
	private $authcode;
	private $buf;
	private $ctr;
	
	function __construct($password, $opt = null) {
		if (!$opt) {$opt = array();}
		$opt += array("version" => 2, "strength" => 3, "salt" => null, "mode" => static::MODE_ENCRYPT);
		$this->version = $opt["version"];
		$this->strength = $opt["strength"];
		$this->mode = $opt["mode"];
		$this->salt = isset($opt["salt"]) ? $opt["salt"] : $this->get_salt();
		$this->dk = $this->pbkdf2($password);
		$this->hmac = hash_init('sha1', HASH_HMAC, $this->dk["authkey"]);
		$this->authcode = null;
		$this->buf = "";
		$this->ctr = array(0, 0, 0, 0);
		$this->updated = false;
		$this->finalized = false;
	}
	
	function finalize() {
		$this->finalized = true;
		return $this->buf ? $this->update("", true) : "";
	}
	
	function get_authcode() {
		if ($this->authcode !== null) {return $this->authcode;}
		$this->authcode = substr(hash_final($this->hmac, true), 0, 10);
		return $this->authcode;
	}
	
	function get_nonce() {
		if (($this->ctr[0]++) >= 0xffffffff) {$this->ctr[0] = 0;
			if (($this->ctr[1]++) >= 0xffffffff) {$this->ctr[1] = 0;
				if (($this->ctr[2]++) >= 0xffffffff) {$this->ctr[2] = 0;$this->ctr[3]++;}}}
		return pack('VVVV', $this->ctr[0], $this->ctr[1], $this->ctr[2], $this->ctr[3]);
	}
	
	function get_salt() {
		if ($this->salt) {return $this->salt;}
		return ZipCrypto::randbytes(4 + 4 * $this->strength);
	}
	
	function get_verify() {
		return $this->dk['verify'];
	}
	
	function pbkdf2($password) {
		$keysize = 8 + 8 * $this->strength;
		$bytes = openssl_pbkdf2($password, $this->get_salt(), 2 + 2 * $keysize, 1000);
		return array(
			"enckey" => substr($bytes, 0, $keysize),
			"authkey" => substr($bytes, $keysize, $keysize),
			"verify" => substr($bytes, 2 * $keysize, 2)
		);
	}
	
	function update($data, $flush = false) {
		$this->updated = true;
		$out = "";
		if ($this->buf) {
			$data = $this->buf . $data;
			$this->buf = "";
		}
		$len = strlen($data);
		$blen = $len % 16;
		if (!$flush && $blen > 0) {
			$this->buf = substr($data, $len-$blen, $blen);
			$data = substr($data, 0, $len-$blen);
			$len -= $blen;
		}
		for($pos = 0; $pos<$len; $pos += 16) {
			$block = substr($data, $pos, 16);
			if ($this->mode === static::MODE_DECRYPT) {hash_update($this->hmac, $block);}
			$block = openssl_encrypt($block, 'aes-256-ctr',
					$this->dk["enckey"], OPENSSL_RAW_DATA,
					$this->get_nonce());
			if ($this->mode === static::MODE_ENCRYPT) {hash_update($this->hmac, $block);}
			$out .= $block;
		}
		return $out;
	}
	
	static function decrypt($data, $password) {
		$opt = array("strength" => 3, "salt" => substr($data, 0, 16), "mode" => static::MODE_DECRYPT);
		$aex = new AExCrypto($password, $opt);
		if ($aex->get_verify() !== substr($data, 16, 2)) {return false;} //bad password
		$encrypted = substr($data, 18, strlen($data) - 28);
		$out = $aex->update($encrypted) . $aex->finalize();
		if ($aex->get_authcode() !== substr($data, strlen($data) - 10, 10)) {return false;} //Incorrect hash
		return $out;
		return $out;
	}
	
	static function encrypt($data, $password) {
		$aex = new AExCrypto($password, array("mode" => static::MODE_ENCRYPT));
		$out = $aex->get_salt() . $aex->get_verify();
		$out .= $aex->update($data);
		$out .= $aex->finalize();
		$out .= $aex->get_authcode();
		return $out;
	}
}

class Log {
	const DEBUG = 0;
	const INFO  = 1;
	const WARN  = 2;
	const ERROR = 4;
	private $data;
	private $level;
	private $fh;
	
	function __construct($opt = null) {
		if (!$opt) {$opt = array();}
		$opt += array("level" => 1);
		$this->data = array();
		$this->level = $opt["level"];
		$this->fh = isset($opt["path"]) ? fopen($opt["path"], "ab") : null;
	}
	
	function __destruct() {
		if ($this->fh) {if (count($this->data)) {$this->flush();}fclose($this->fh);}
	}
	
	function flush() {
		if ($this->fh) {
			$levels = array(0 => 'D', 1 => 'I', 2 => 'W', 4 => 'E');
			foreach($this->data as $ent) {
				fwrite($this->fh, $levels[$ent[0]] . "," . date('Y-m-dTH:i:s', $ent[1]) . ' : ' . $ent[2] . "\n");
			}
		}
		$this->data = array();
	}
	
	function get_data() {
		return $this->data;
	}
	
	function get_level($name = null) {
		if ($name && is_string($name)) {
			$names = array("DEBUG"=>static::DEBUG,"INFO"=>static::INFO,"WARN"=>static::WARN,"ERROR"=>static::ERROR);
			$name = str_to_upper($name);
			return isset($names[$name]) ? $names[$name] : 1;
		} elseif (is_int($name)) {
			return $name;
		}
		return $this->level;
	}
	
	function log($msg, $level = null) {
		if ($level === null) {$level = static::INFO;}
		if (is_string($level)) {$level = $this->get_level($level);}
		if ($this->level > $level) {return;}
		$this->data[] = array($level, time(), $msg);
		if ($this->fh && count($this->data) > 1000) {$this->flush();}
	}
	
	function set_level($level) {
		if (is_string($level)) {$level = $this->get_level($level);}
		$this->level = $level;
	}
}

/**
 * AEx encryption filter
 */
class AExEncryptionFilter extends \php_user_filter {
	public $stream; //for stream_bucket_new()
	
	#[\ReturnTypeWillChange]
	function filter($in, $out, &$consumed, $closing) {
		$log = isset($this->params["log"]) ? $this->params["log"] : null;
		if ($log) {$log->log("in:".get_resource_type($in).",consumed:".var_export($consumed,true).",closing:".($closing?'T':'f'));}
		$loops = 0;
		$aex = $this->params["aex"];
		$hdr = $aex->updated ? "" : ($aex->get_salt() . $aex->get_verify());
		while ($bucket = stream_bucket_make_writeable($in)) {
			$consumed += $bucket->datalen;
			if ($log) {$log->log("[".($loops++)."] datalen:".$bucket->datalen.",consumed:".var_export($consumed,true).",closing:".($closing?'T':'f'));}
			$bucket->data = $hdr . $aex->update($bucket->data);
			$hdr = "";
			stream_bucket_append($out, $bucket);
		}
		if ($closing && !$aex->finalized) {
			if ($log) {$log->log("finalize");}
			$bucket = stream_bucket_new($this->stream, $aex->finalize() . $aex->get_authcode());
			stream_bucket_append($out, $bucket);
		}
		return PSFS_PASS_ON;
	}
}
stream_filter_register("rezipe.aescryptofilter", 'Rezipe\AExEncryptionFilter') or die("Failed to register filter");

/**
 * empty filter
 */
class EmptyFilter extends \php_user_filter {
	#[\ReturnTypeWillChange]
	function filter($in, $out, &$consumed, $closing) {
		while ($bucket = stream_bucket_make_writeable($in)) {
			$consumed += $bucket->datalen;
			$bucket->data = "";
			stream_bucket_append($out, $bucket);
		}
		return PSFS_PASS_ON;
	}
}
stream_filter_register("rezipe.emptyfilter", 'Rezipe\EmptyFilter') or die("Failed to register filter");

/**
 * CRC-32 filter
 */
class Crc32Filter extends \php_user_filter {
	#[\ReturnTypeWillChange]
	function filter($in, $out, &$consumed, $closing) {
		$hasher = $this->params["hasher"];
		while($bucket = stream_bucket_make_writeable($in)) {
			$consumed += $bucket->datalen;
			hash_update($hasher, $bucket->data);
			stream_bucket_append($out, $bucket);
		}
		return PSFS_PASS_ON;
	}
}
stream_filter_register("rezipe.crc32filter", 'Rezipe\Crc32Filter') or die("Failed to register filter");

/**
 * bytelength count filter
 */
class StrlenFilter extends \php_user_filter {
	#[\ReturnTypeWillChange]
	function filter($in, $out, &$consumed, $closing) {
		while ($bucket = stream_bucket_make_writeable($in)) {
			$consumed += $bucket->datalen;
			$this->params["size"]->total += $bucket->datalen;
			stream_bucket_append($out, $bucket);
		}
		return PSFS_PASS_ON;
	}
}
stream_filter_register("rezipe.strlenfilter", 'Rezipe\StrlenFilter') or die("Failed to register filter");

class TransferFilter extends \php_user_filter {
	#[\ReturnTypeWillChange]
	function filter($in, $out, &$consumed, $closing) {
		$transfer = $this->params["transfer"];
		while($bucket = stream_bucket_make_writeable($in)) {
			$consumed += $bucket->datalen;
			if ($transfer) {fwrite($transfer, $bucket->data);}
			stream_bucket_append($out, $bucket);
		}
		return PSFS_PASS_ON;
	}
}
stream_filter_register("rezipe.transferfilter", 'Rezipe\TransferFilter') or die("Failed to register filter");

class ZipcryptoFilter extends \php_user_filter {
	#[\ReturnTypeWillChange]
	function filter($in, $out, &$consumed, $closing) {
		$zc = $this->params["zc"];
		$to_set_enchdr = false;
		while ($bucket = stream_bucket_make_writeable($in)) {
			$consumed += $bucket->datalen;
			$buf = $bucket->data;
			if (!$zc->has_encryption_header()) {
				$to_set_enchdr = true;
				$hdr = $zc->random_header();
				$buf = $hdr . $buf;
			}
			$bucket->data = $zc->update($buf, true);
			if ($to_set_enchdr) {
				$hdr = substr($bucket->data, 0, 12);
				$zc->set_encryption_header($hdr);
				$to_set_enchdr = false;
			}
			stream_bucket_append($out, $bucket);
		}
		return PSFS_PASS_ON;
	}
}
stream_filter_register("rezipe.zipcryptofilter", 'Rezipe\ZipcryptoFilter') or die("Failed to register filter");


class DataConverter {
	private $path;
	private $data;
	public $option;
	public $crc32_params;
	public $zlib_params;
	public $transfer_params;
	public $strlen_params;
	public $zipcrypto_params;
	public $aescrypto_params;
	public $buflen;
	private $crc32_filter;
	private $zlib_filter;
	private $transfer_filter;
	private $strlen_filter;
	private $empty_filter;
	private $zipcrypto_filter;
	private $aescrypto_filter;
	private $hasher;
	private $crc32;
	private $compsize;
	
	function __construct() {
		$this->path = null;
		$this->data = null;
		$this->crc32_params = array("hasher" => null);
		$this->zlib_params = array('level' => -1, 'window' => -15, 'memory' => 9);
		$this->transfer_params = array("transfer" => null);
		$sizeObj = new \stdClass();
		$sizeObj->total = 0;
		$this->strlen_params = array("size" => $sizeObj);
		$this->zipcrypto_params = array("zc" => null);
		$this->aescrypto_params = array("aex" => null); //"log" => new Log(array("path" => "aex_log.log"))
		$this->buflen = 32*1024;
		$this->crc32 = null;
		$this->compsize = null;
		$this->hasher = null;
	}
	
	function get_compsize() {
		if (!$this->compsize) {$this->set_compsize();}
		return $this->compsize;
	}
	
	function get_crc32($pack = "") {
		if (!$this->crc32) {$this->set_crc32();}
		$crc32 = $this->crc32;
		if ($pack) {
			$crc32 = unpack($pack, $crc32)[1];
		}
		return $crc32;
	}
	
	function run($opt = null) {
		if (!$opt) {$opt = array();}
		$opt = $opt + $this->option;
		$mem = fopen("php://memory", "wb");
		if ($opt["crc32"]) {$this->set_crc32_filter($mem, $this->hasher);}
		if ($opt["zlib"]) {$this->set_zlib_filter($mem);}
		if (is_string($opt["zipcrypto"]) && is_int($opt["crc32"])) {
			$this->set_zipcrypto_filter($mem, $opt["zipcrypto"], $opt["crc32"]);
		} elseif (is_string($opt["aescrypto"])) {
			$this->set_aescrypto_filter($mem, $opt["aescrypto"]);
		}
		if ($opt["transfer"]) {$this->set_transfer_filter($mem, $opt["transfer"]);}
		if (true || $opt["strlen"]) {$this->set_strlen_filter($mem);}
		$this->set_empty_filter($mem); //必ず末尾にEmptyFilterをセット
		if ($this->data) {
			fwrite($mem, $this->data);
		} else {
			$io_r = fopen($this->path, 'rb');
			while(!feof($io_r)) {
				$buf = fread($io_r, $this->buflen);
				fwrite($mem, $buf);
			}
			fclose($io_r);
		}
		fclose($mem);
		if ($opt["crc32"] === true) {$this->set_crc32();}
		if (true || $opt["strlen"]) {$this->set_compsize();}
	}
	
	function set_aescrypto_filter($io, $password) {
		$aex = new AExCrypto($password);
		$this->aescrypto_params["aex"] = $aex;
		$this->aescrypto_filter = stream_filter_append($io, "rezipe.aescryptofilter",
				STREAM_FILTER_WRITE, $this->aescrypto_params);
		
	}
	
	function set_compsize($reset = true) {
		$this->compsize = $this->strlen_params["size"]->total;
		if ($reset) {$this->strlen_params["size"]->total = 0;}
	}
	
	function set_crc32($reset = true) {
		$this->crc32 = hash_final($this->hasher, true);
		if ($reset) {$this->hasher = null;}
	}
	
	function set_crc32_filter($io, $hasher) {
		$this->crc32_params["hasher"] = $hasher;
		$this->crc32_filter = stream_filter_append($io, "rezipe.crc32filter",
				STREAM_FILTER_WRITE, $this->crc32_params);
	}
	
	function set_empty_filter($io) {
		$this->empty_filter = stream_filter_append($io, "rezipe.emptyfilter",
				STREAM_FILTER_WRITE);
	}
	
	function set_strlen_filter($io) {
		$this->strlen_filter = stream_filter_append($io, "rezipe.strlenfilter",
				STREAM_FILTER_WRITE, $this->strlen_params);
	}
	
	function set_transfer_filter($io, $output = false) {
		if ($output) {$this->transfer_params["transfer"] = $output;}
		$this->transfer_filter = stream_filter_append($io, "rezipe.transferfilter",
				STREAM_FILTER_WRITE, $this->transfer_params);
	}
	
	function set_zipcrypto_filter($io, $password, $crc32) {
		$zc = new ZipCrypto();
		$zc->set_password($password);
		$zc->set_crc32($crc32);
		$this->zipcrypto_params["zc"] = $zc;
		$this->zipcrypto_filter = stream_filter_append($io, "rezipe.zipcryptofilter",
				STREAM_FILTER_WRITE, $this->zipcrypto_params);
		
	}
	
	function set_zlib_filter($io) {
		$this->zlib_filter = stream_filter_append($io, 'zlib.deflate',
				STREAM_FILTER_WRITE, $this->zlib_params);
	}
	
	public static function convert($opt = null) {
		$my = static::init($opt);
		$my->run();
		return $my;
	}
	
	public static function init($opt = null) {
		if (!$opt) {$opt = array();}
		$my = new static();
		$opt = $opt + array("path" => null, "data" => false,
				"zlib" => false, "transfer" => false, "strlen" => false,
				"crc32" => false, "buffer" => null, "zipcrypto" => null,
				"aescrypto" => null);
		$my->option = $opt;
		if ($opt["path"]) {$my->path = $opt["path"];}
		if ($opt["data"]) {$my->data = $opt["data"];}
		if ($opt["crc32"] === true || is_string($opt["zipcrypto"]) &&
				is_int($opt["crc32"])) {$my->hasher = hash_init('crc32b');}
		if ($opt["buffer"]) {$my->buflen = $opt["buffer"];}
		return $my;
	}
}

class ExtensibleDataField {
	public $header_id;
	public $data_size;

	const HEADER_ID_ZIP64   = 0x0001;
	const HEADER_ID_NTFS    = 0x000a;
	const HEADER_ID_UNIX    = 0x000d;
	const HEADER_ID_EXTIME  = 0x5455;
	const HEADER_ID_UPATH   = 0x7075;
	const HEADER_ID_UNIX2   = 0x7855;
	const HEADER_ID_AEX     = 0x9901;
}

// 0x0001
// *** 64bit only ***
class Zip64ExtendedInformation extends ExtensibleDataField {
	public $size;      // Original uncompressed file size
	public $compsize;  // Size of compressed data
	public $offset;    // Offset of local header record
	public $diskstart; // Number of the disk on which this file starts
	
	function __construct($opt = null) {
		if (!$opt) {$opt = array();}
		$opt += array("size" => 0, "compsize" => 0, "offset" => 0, "diskstart" => 0, "cd" => false);
		$this->header_id = static::HEADER_ID_ZIP64;
		$this->data_size = 0;
		$this->size = $opt["size"];
		$this->compsize = $opt["compsize"];
		$this->offset = $opt["offset"];
		$this->diskstart = $opt["diskstart"];
		$this->for_cd = $opt["cd"];
		if (!$this->for_cd) { //only size, compsize 8+8
			$this->data_size = 16;
		} else {
			if ($this->size > 0xffffffff) {$this->data_size += 8;}
			if ($this->compsize > 0xffffffff) {$this->data_size += 8;}
			if ($this->offset > 0xffffffff) {$this->data_size += 8;}
			if ($this->diskstart > 0xffff) {$this->data_size += 4;}
		}
	}
	
	function bytes() {
		return 4 + $this->data_size;
	}
	
	function to_s() {
		if (!$this->for_cd) {
			return pack('vvPP',
				$this->header_id,
				$this->data_size,
				$this->size,
				$this->compsize);
		}
		$val = pack('vv', $this->header_id, $this->data_size);
		if ($this->size > 0xffffffff) {$val .= pack('P', $this->size);}
		if ($this->compsize > 0xffffffff) {$val .= pack('P', $this->compsize);}
		if ($this->offset > 0xffffffff) {$val .= pack('P', $this->offset);}
		if ($this->diskstart > 0xffff) {$val .= pack('V', $this->diskstart);}
		return $val;
	}
}

// 0x000a
class NTFSExtraField extends ExtensibleDataField {
	const WINDOWS_TICK      = 10000000;
	const SEC_TO_UNIX_EPOCH = 11644473600; // "01-Jan-1970" ~ "01-Jan-1601"
	const UINT32_MAX        = '4294967296';
	
	function __construct($mtime, $atime = null, $ctime = null) {
		$this->header_id = static::HEADER_ID_NTFS;
		$this->data_size = 32;
		$this->reserved = 0;
		$atime = $atime ? $atime : $mtime;
		$ctime = $ctime ? $ctime : $atime;
		$tag1 = static::create_tag(array(
			"tag_id" => 1,
			"mtime" => $mtime,
			"atime" => $atime,
			"ctime" => $ctime
		));
		$this->tags = array($tag1);
	}
	
	function bytes() {
		return 36;
	}
	
	function to_s() {
		return pack('vvV',
				$this->header_id,
				$this->data_size,
				$this->reserved) .
				$this->tags[0];
	}
	
	static function create_tag($params) {
		$tag_id = $params['tag_id'];
		if (PHP_INT_SIZE === 8 && PHP_MAJOR_VERSION >= 7) {
			$data = pack('PPP',
					static::time2longlong($params['mtime']),
					static::time2longlong($params['atime']),
					static::time2longlong($params['ctime']));
		} else {
			$times = array(
				static::time2longs($params['mtime']),
				static::time2longs($params['atime']),
				static::time2longs($params['ctime'])
			);
			$data = pack('VVVVVV',
					$times[0][1], $times[0][0],
					$times[1][1], $times[1][0],
					$times[2][1], $times[2][0]);
		}
		$size = strlen($data);
		return pack('vv', $tag_id, $size) . $data;
	}
	
	/**
	 * 時間をNTSDate(64bit整数)に変換する。
	 * 64bit整数をサポートしているPHP7以上でないと動作しない
	 * @param {Integer} $time 時間
	 * @return {Integer} NTFSDate
	 */
	static function time2longlong($time) {
		return intval(($time + static::SEC_TO_UNIX_EPOCH) * static::WINDOWS_TICK);
	}
	
	/**
	 * 時間をNTFSDateに変換し32bit整数2つの配列を返す。
	 * BC Math関数で大きな整数の計算をして分割している
	 * @param {Integer}    $time 時間
	 * @return {Integer[]} NTFSDateを分割したもの(上位32bit, 下位32bitの順)
	 */
	static function time2longs($time) {
		$num64 = bcmul(bcadd('' . $time,
				static::SEC_TO_UNIX_EPOCH),
				static::WINDOWS_TICK);
		$l32 = bcdiv($num64, static::UINT32_MAX);
		$r32 = bcmod($num64, static::UINT32_MAX);
		return array(intval($l32), intval($r32));
	}
}

// 0x000d - Unix0
class UnixExtraField extends ExtensibleDataField {
	public $atime;
	public $mtime;
	public $uid;
	public $gid;
	public $var;
	
	function __construct($opt = null) {
		if (!$opt) {$opt = array();}
		$opt += array("atime" => time(), "mtime" => time(), "uid" => 32767, "gid" => 0, "var" => "");
		$this->header_id = static::HEADER_ID_UNIX;
		$this->data_size = 12 + strlen($opt["var"]);
		$this->atime = $opt["atime"];
		$this->mtime = $opt["mtime"];
		$this->uid = $opt["uid"];
		$this->gid = $opt["gid"];
		$this->var = $opt["var"];
	}
	
	function bytes() {
		return 4 + $this->data_size;
	}
	
	function to_s() {
		return pack('vvVVvv',
				$this->header_id,
				$this->data_size,
				$this->atime,
				$this->mtime,
				$this->uid,
				$this->gid) .
				$this->var;
	}
}

// 0x7075 - Info-ZIP Unicode Path Extra Field
class UnicodePathExtraField extends ExtensibleDataField {
	public $path;
	public $unicode_path;
	public $version;
	public $crc;
	
	function __construct($opt = null) {
		$this->header_id = static::HEADER_ID_UPATH;
		$this->path = $opt["path"];
		$this->unicode_path = $this->path;
		$this->version = 1;
		$this->crc = crc32($this->unicode_path);
		$this->data_size = 5 + strlen($this->unicode_path);
	}
	
	function bytes() {
		return 4 + $this->data_size;
	}
	
	function to_s() {
		return pack('vvCV',
				$this->header_id,
				$this->data_size,
				$this->version,
				$this->crc) .
				$this->unicode_path;
	}
}

// 0x7855 - Unix2
class UnixExtraFieldType2 extends ExtensibleDataField {
	public $uid;
	public $gid;
	private $for_cd;
	
	function __construct($opt = null) {
		if (!$opt) {$opt = array();}
		$opt += array("uid" => 65534, "gid" => 0, "cd" => false);
		$this->for_cd = $opt["cd"];
		$this->header_id = static::HEADER_ID_UNIX2;
		$this->data_size = $this->for_cd ? 0 : 4;
		$this->uid = $opt["uid"];
		$this->gid = $opt["gid"];
	}
	
	function bytes() {
		return 4 + $this->data_size;
	}
	
	function to_s() {
		return pack('vv',
				$this->header_id,
				$this->data_size) .
				($this->for_cd ? '' : pack('vv',
				$this->uid,
				$this->gid));
	}
}

// 0x5455
class ExtendedTimestamp extends ExtensibleDataField {
	private $flags;
	private $mtime;
	private $atime;
	private $ctime;
	private $flags_cnt;
	private $for_cd;
	
	function __construct($opt = null) {
		if (!$opt) {$opt = array();}
		$opt += array("flags" => 7, "mtime" =>  time(), "atime" =>  time(), "ctime" => time(), "cd" => false);
		$this->header_id = static::HEADER_ID_EXTIME;
		$this->flags = $opt["flags"];
		$this->mtime = $opt["mtime"];
		$this->atime = $opt["atime"];
		$this->ctime = $opt["ctime"];
		$this->flags_cnt = $opt["flags"] >= 4 ? 3 : (
				$opt["flags"] >= 2 ? 2 : (
				$opt["flags"] ? 1 : 0));
		$this->for_cd = $opt["cd"];
		$this->data_size = 1 + ($this->for_cd ? ($this->flags_cnt ? 4 : 0) : (4 * $this->flags_cnt));
	}
	
	function bytes() {
		return 4 + $this->data_size;
	}
	
	function to_s() {
		if ($this->for_cd) {
			return pack('vvC', $this->header_id, $this->data_size, $this->flags) .
					($this->flags ? pack('V', $this->mtime) : '');
		}
		return pack('vvC', $this->header_id, $this->data_size, $this->flags) .
				($this->flags_cnt > 0 ? pack('V', $this->mtime) : '') .
				($this->flags_cnt > 1 ? pack('V', $this->atime) : '') .
				($this->flags_cnt > 2 ? pack('V', $this->ctime) : '');
	}
}

// 0x9901 AE-x encryption structure
class AExEncryptionExtraField extends ExtensibleDataField {
	private $vender_id;
	private $vender_version;
	private $strength;
	private $method;
	
	function __construct($opt = null) {
		if (!$opt) {$opt = array();}
		$opt += array("version" => 2, "strength" => 3, "method" => 0);
		$this->header_id = static::HEADER_ID_AEX;
		$this->data_size = 7;
		$this->vender_version = $opt["version"];
		$this->vender_id = 0x4541; //'AE'
		$this->strength = $opt["strength"];
		if (is_string($this->strength)) {
			if (strpos($this->strength, '256') !== false) {
				$this->strength = 3; //AES256
			} elseif (strpos($this->strength, '192') !== false) {
				$this->strength = 2; //AES192
			} elseif (strpos($this->strength, '128') !== false) {
				$this->strength = 1; //AES128
			} else {
				$this->strength = 3;
			}
		}
		$this->method = $opt["method"];
	}
	
	function bytes() {
		return 4 + $this->data_size;
	}
	
	function to_s() {
		return pack('vvvvCv', $this->header_id, $this->data_size,
				$this->vender_version, $this->vender_id,
				$this->strength, $this->method);
	}
}
