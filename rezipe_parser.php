<?php
namespace Rezipe;

const VERSION = '0.1.0';
const FE_SIGNATURE = 0x04034b50; # "PK\x03\x04"
const DD_SIGNATURE = 0x08074b50; # "PK\x07\x08"
const CD_SIGNATURE = 0x02014b50; # "PK\x01\x02"
const EOCD_SIGNATURE = 0x06054b50; # "PK\x05\x06"
const Z64_EOCDR_SIGNATURE = 0x06064b50; # "PK\x06\x06"
const Z64_EOCDL_SIGNATURE = 0x07064b50; # "PK\x06\x07"

function puts($msg) {
	echo $msg . "\n";
}

function p($obj) {
	//var_export($obj);
	$out = json_encode($obj,
			JSON_UNESCAPED_UNICODE |
			JSON_NUMERIC_CHECK,
			4096);
	if ($out !== false && $out !== null) {
		echo $out . "\n";
	} else {
		if ($err = json_last_error()) {
			echo "JSON_ERROR[${err}]\n";
		}
		echo serialize($obj) . "\n";
	}
}

function binesc($obj) {
	$escaped = array();
	foreach($obj as $k => $v) {
		if (is_string($v) && !json_encode($v)) {$v = bin2hex($v);}
		$escaped[$k] = $v;
	}
	return $escaped;
}

class ZipParser {
	public $check_crc32;
	public $password;
	public $path;
	public $stat;
	public $fh;
	
	function __construct($path) {
		$this->path = $path;
		$this->check_crc32 = false;
		$this->password = null;
		$this->fh = null;
		$this->stat = array();
	}
	
	function close($msg = null) {
		if ($this->fh) {fclose($this->fh);}
		if ($msg) {
			if (!isset($this->stat['errors'])) {$this->stat['errors'] = array();}
			$this->stat['errors'][] = $msg;
			echo $msg . "\n";
		}
	}
	
	function parse() {
		$path = $this->path;
		$check_crc32 = $this->check_crc32;
		puts("### Parser info");
		puts('  $path: ' . $path);
		puts('  $check_crc32: ' . $check_crc32);
		$this->stat = $stat = array(
			'size' => filesize($path),
			'filename' => $path,
			'mtime' => filemtime($path)
		);
		puts("### File info");
		p($stat);
		$stat['errors'] = array();
		$this->fh = $fh = fopen($path, 'rb');

		# ファイル終端からEOCDを探す。
		# コメント無しなら22byteだが念のため32byteずつ遡る
		$pos = $stat['size'];
		$eocd_idx = null;
		$eocd_sig = pack('V', EOCD_SIGNATURE);
		$buf = "";
		while (!$eocd_idx && $pos > 32) {
			$pos -= 32;
			fseek($fh, $pos);
			$buf .= fread($fh, 32);
			$eocd_idx = strrpos($buf, $eocd_sig);
			if (strlen($buf) > 0xffff) {return $this->close("Not found EOCD");}
			if ($eocd_idx === false) {continue;}
			#p [BIN_EOCD_SIGNATURE, pos + eocd_idx, [pos,eocd_idx]]
			$stat['eocd'] = $pos + $eocd_idx;
			$pos = $stat['eocd'];
		}

		# EOCDからCD数と最初のCDの位置を取得
		if (!isset($stat['eocd'])) {return $this->close("Not found EOCD");}
		fseek($fh, $stat['eocd'] + 4);
		$buf = fread($fh, 18);
		$r = unpack('vdisknum/vdiskstart/vdiskcdtotal/vcdtotal/Vcdsize/Voffset/vcommlen', $buf);
		puts("### EndOfCentralDirectory : 0x" . sprintf('%08x', $pos));
		p(array(bin2hex($buf), strlen($buf), $r));
		# ZIP64 format は、いずれか1つのフィールドが0xffffffff(0xffff)で、Zip64 EOCD がある
		$is_zip64format = false;
		if ($r['disknum'] === 0xffff || $r['diskstart'] === 0xffff || $r['diskcdtotal'] === 0xffff ||
				$r['cdtotal'] === 0xffff || $r['cdsize'] === 0xffffffff || $r['offset'] === 0xffffffff) {
			fseek($fh, $stat['eocd'] - 20);
			$is_zip64format = unpack('V', fread($fh, 4))[1] === Z64_EOCDL_SIGNATURE;
			puts("### seek ZIP64 EOCD locator and record : 0x" .
					sprintf('%08x', $stat['eocd']) .
					" => " . ($is_zip64format ? 'FOUND' : 'NOT FOUND'));
		}
		if ($is_zip64format) {
			# ZIP64 end of central directory locator, - record を探す
			# ZIP64 end of central directory locator は 20Byte(sig:4, z64diskstart:4, z64offset:8, disktotal:4)
			fseek($fh, $stat['eocd'] - 20);
			$buf = fread($fh, 20);
			$r = unpack('Vsig/Vz64diskstart/Pz64offset/Vdisktotal', $buf);
			$r = array();
			if ($r['sig'] !== Z64_EOCDL_SIGNATURE) {
				return $this->close("Not found Zip64 EOCD locator");
			}
			p($r);
			$pos = $r['z64offset'];
			# ZIP64 end of central directory record は 56Byte+?(sig:4, size:8, madeby:2, version:2,
			#	 disknum:4, diskstart:4, diskcdtotal:8, cdtotal:8, cdsize:8, offset:8, :?)
			fseek($fh, $pos);
			$buf = fread($fh, 56);
			$r = unpack('Vsig/Psize/vmadeby/vversion/Vdisknum/Vdiskstart/Pdisktotal/Pcdtotal/Pcdsize/Poffset', $buf);
			if ($r['sig'] !== Z64_EOCDR_SIGNATURE) {
				return $this->close("Not found Zip64 EOCD Record");
			}
			puts("### Zip64EndOfCentralDirectoryRecord : " . sprintf('%08x', pos));
			p($r);
		}
		$stat['cd0']     = $r['offset'];
		$stat['cdtotal'] = $r['cdtotal'];
		$pos = $stat['cd0'];
		
		# 全CDの情報を取得
		$z64target = array(
			'fields' => array('size', 'compsize', 'offset', 'diskstart'),
			'size' => array('size' => 8, 'compsize' => 8, 'offset' => 8, 'diskstart' => 4),
			'max' => array('size' => 0xffffffff, 'compsize' => 0xffffffff, 'offset' => 0xffffffff, 'diskstart' => 0xffff)
		);
		if (!isset($stat['cd0'])) {return $this->close("Not found start of CentralDirectory");}
		$stat['cd_list'] = array();
		for($i = 0; $i < $stat['cdtotal']; $i++) {
			fseek($fh, $pos);
			$buf = fread($fh, 46);
			$r = unpack('Vsig/vmadeby/vversion/vflag/vmethod/vtime/vdate/' .
					'Vcrc32/Vcompsize/Vsize/vlen/vexlen/vcommlen/vdiskstart/' .
					'vinattr/Vexattr/Voffset', $buf);
			#fn,ex,comm読み込み
			$r['filename'] = fread($fh, $r['len']);
			$r['exdata'] = $r['exlen'] ? fread($fh, $r['exlen']) : '';
			$r['comm'] = $r['commlen'] ? fread($fh, $r['commlen']) : '';
			$is_utf8 = ($r['flag'] & (1 << 11)) === (1 << 11);
			if (!$is_utf8) {$r['filename'] = mb_convert_encoding($r['filename'], 'UTF-8', 'CP932');}  #CP932を想定
			$is_encrypted = ($r['flag'] & 1) === 1;
			puts("### CentralDirectory[${i}] : 0x" . sprintf('%08x', $pos) . " - ${r['filename']}" . ($is_encrypted ? ' (Encrypted)' : ''));
			# size, compsize, offset, diskstart が 0xffffffff (0xffff) だった場合exdataをparse
			$z64overflow_fields = array();
			foreach($z64target['fields'] as $fld) {
				if ($r[$fld] !== $z64target['max'][$fld]) {continue;}
				$z64overflow_fields[] = $fld;
			}
			if ($r['exlen'] > 0 && count($z64overflow_fields) > 0) {
				# ZIP64 extra filed の Header ID は 0x0001
				#	 Data Sizeは0xffffffff(0xffff)だったフィールドの数によって変化し
				#	 Dataの並び順は固定で size, compsize, offset, diskstart の順になる。
				#	 つまり、overflowしていないフィールドは省略される。
				#	 例えば offset だけがoverflowした場合は以下のような12byteになる
				#		 HeaderID :	0x0001 (2B)
				#		 Data Size:	0x0008 (2B)
				#		 offset	 :	0x0123456789ABCDEF (8B)
				$z64exdata = null;
				foreach(static::parse_exdata($r['exdata']) as $exd) {
					if ($exd['id'] === 0x0001) {$z64exdata = $exd;break;}
				}
				$exdata_pos = 0;
				$n = 0;
				foreach($z64overflow_fields as $fld) {
					$fld_size = $z64target['size'][$fld];
					$v = substr($z64exdata['data'], $exdata_pos, $fld_size);
					$num = unpack($fld_size === 4 ? 'V' : 'P', $v)[1];
					puts("  [${n}] ZIP64 overflow field[${fld}] => replaced from extra field value[${num}]");
					$r[$fld] = $num;
					$exdata_pos += $fld_size;
					$n++;
				}
			}
			p(array(bin2hex(substr($buf, 0, 20)) . "...", strlen($buf), binesc($r)));
			$stat['cd_list'][] = $r;
			$pos += 46 + $r['len'] + $r['exlen'] + $r['commlen'];
			# check
			if ($r['sig'] !== CD_SIGNATURE) {
				$stat['errors'][] = "CD[${i}] Invalid signature: expected=>".dechex(CD_SIGNATURE).", actual=>" . dechex($r['sig']);
			}
		}
		
		# 各CDからファイル情報取得
		if (!isset($stat['cd_list']) || count($stat['cd_list']) === 0) {
			return $this->close("Not found list of CentralDirectory");
		}
		$stat['files'] = array();
		$i = 0;
		foreach($stat['cd_list'] as $cd) {
			$pos = $cd['offset'];
			fseek($fh, $pos);
			$buf = fread($fh, 30);
			$r = unpack('Vsig/vversion/vflag/vmethod/vtime/vdate/' .
					'Vcrc32/Vcompsize/Vsize/vlen/vexlen', $buf);
			#fn,ex
			$r['filename'] = fread($fh, $r['len']);
			$r['exdata'] = $r['exlen'] ? fread($fh, $r['exlen']) : '';
			$is_utf8 = ($r['flag'] & (1 << 11)) === (1 << 11);
			if (!$is_utf8) {$r['filename'] = mb_convert_encoding($r['filename'], 'UTF-8', 'CP932');}  #CP932を想定
			$enc_header = '';
			if ($is_encrypted = ($r['flag'] & 1) == 1) {$enc_header = fread($fh, 12);}
			puts("### FileEntry[${i}] : 0x" . sprintf('%08x', $pos) . " - " . $r['filename'] . ($is_encrypted ? ' (Encrypted)' : ''));
			if ($is_encrypted) {puts("  [EncryptionHeader] : " . bin2hex($enc_header));}
			# size, compsize が 0xffffffff だった場合exdataをparse
			$z64overflow_fields = array();
			foreach($z64target['fields'] as $fld) {
				if (!isset($r[$fld])) {continue;}
				if ($r[$fld] === $z64target['max'][$fld]) {$z64overflow_fields[] = $fld;}
			}
			if ($r['exlen'] > 0 && count($z64overflow_fields) > 0) {
				$z64exdata = null;
				foreach(static::parse_exdata($r['exdata']) as $exd) {
					if ($exd['id'] === 0x0001) {$z64exdata = $exd;break;}
				}
				$exdata_pos = 0;
				$n = 0;
				foreach($z64overflow_fields as $fld) {
					$fld_size = $z64target['size'][$fld];
					$v = substr($z64exdata['data'], $exdata_pos, $fld_size);
					$num = unpack($fld_size === 4 ? 'V' : 'P', $v)[1];
					puts("  [${n}] ZIP64 overflow field[${fld}] => replaced from extra field value[${num}]");
					$r[$fld] = $num;
					$exdata_pos += $fld_size;
					$n++;
				}
			}
			p(array(bin2hex(substr($buf, 0, 20)) . "...", strlen($buf), binesc($r)));
			$stat['files'][] = $r;
			$use_datadesc = ($r['flag'] & 8) === 8;
			$compsize = $use_datadesc && $r['compsize'] === 0 ? $cd['compsize'] : $r['compsize'];
			$size = $use_datadesc && $r['size'] === 0 ? $cd['size'] : $r['size'];
			$is_directory = !$use_datadesc && $compsize === 0 && $size === 0;
			$pos += 30 + $r['len'] + $r['exlen'] + $compsize;
			# check
			if ($r['sig'] !== FE_SIGNATURE) {
				$stat['errors'][] = "FE[${i}] Invalid signature: expected=>" . dechex(FE_SIGNATURE) . ", actual=>" . dechex($r['sig']);
			}
			if ($check_crc32 && !$is_directory) {

				$ex_crc32 = $use_datadesc && $r['crc32'] === 0 ? $cd['crc32'] : $r['crc32'];
				if ($compsize < 1048576) {
					fseek($fh, $cd['offset'] + 30 + $r['len'] + $r['exlen']);
					$buf = fread($fh, $compsize);
					if ($is_encrypted) {$buf = ZipCrypto::decrypt($buf, $this->password, $ex_crc32);}
					if ($r['method'] === 8) {$buf = gzinflate($buf);}
					$crc32 = crc32($buf);
				} else {
					$de = DataExtracter::extract(array(
							"input" => $fh,
							"offset" => $cd['offset'] + 30 + $r['len'] + $r['exlen'], 
							"compsize" => $compsize,
							"buffer" => 1024*1024,
							"zlib" => $r['method'] === 8,
							"crc32" => $ex_crc32,
							"zipdecrypto" => $is_encrypted ? $this->password : false));
					$crc32 = $de->get_crc32('N');
					//var_export($de->logs);
					if (count($de->logs["E"])) {
						puts("  DataExError:" . implode("\n", $de->logs["E"]));
					}
					if (count($de->logs["I"])) {
						puts("  DataExInfo:" . implode("\n", $de->logs["I"]));
					}
				}
				if ($ex_crc32 === $crc32) {
					puts("  CRC-32: ok " . dechex($crc32));
				} else {
					puts("  CRC-32: NG " . dechex($ex_crc32) . " <=> " . dechex($crc32));
					$stat['errors'][] = "FE[${i}] BAD CRC-32: expected=>" . dechex($ex_crc32) . ", actual=>" . dechex($crc32);
				}
			}
			# general purpose flag Bit3 : DataDescriptor
			if ($use_datadesc && !$is_directory) {
				# 先頭4Bは signature: 0x08074b50 がある場合と
				# 省略されていきなりCRC32がくる場合がある
				# また、size,compsizeが4Byteを超えている場合は8Byteになる
				fseek($fh, $pos);
				$dd = 12;
				$r['crc32'] = unpack('V', fread($fh, 4))[1];
				if ($has_signature = $r['crc32'] === DD_SIGNATURE) {
					$dd += 4;
					$r['crc32'] = unpack('V', fread($fh, 4))[1];
				}
				if ($zip64_dd = $size > 0xffffffff || $compsize > 0xffffffff) {
					$dd += 8;
					$r = unpack('Psize/Pcompsize', fread($fh, 16)) + $r;
				} else {
					$r = unpack('Vsize/Vcompsize', fread($fh, 8)) + $r;
				}
				puts("#### " . ($zip64_dd ? 'ZIP64 ' : '') . "DataDescriptor of FE[${i}] : 0x" . sprintf('%08x', $pos));
				fseek($fh, $pos);
				$buf = fread($fh, $dd);
				p(array(bin2hex(substr($buf, 0, 12)) . "...", $dd, $r['crc32'], $r['size'], $r['compsize']));
				$pos += $dd;
			}
			$i++;
		}
		$this->close();
		return $stat;
	}
	
	static function parse_exdata($exdata) {
		if (!$exdata || strlen($exdata) === 0) {return array();}
		$pos = 0;
		$len = strlen($exdata);
		$entries = array();
		while ($pos < $len) {
			$r = unpack('vid/vsize', substr($exdata, $pos, 4));
			$entries[] = array('id' => $r['id'], 'data' => substr($exdata, $pos+4, $r['size']));
			$pos += 4 + $r['size'];
		}
		return $entries;
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
		$h = $this->key1_h;
		$l = $this->key1_l + ($this->key0 & 0xff);
		if ($l > 0xffff) {
			$h = ($h + ($l >> 16)) & 0xffff;
			$l &= 0xffff;
		}
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
 * empty filter
 */
class EmptyFilter extends \php_user_filter {
	function filter($in, $out, &$consumed, $closing) {
		while($bucket = stream_bucket_make_writeable($in)) {
			$consumed += $bucket->datalen;
			$bucket->data = "";
			stream_bucket_append($out, $bucket);
		}
		return PSFS_PASS_ON;
	}
}
stream_filter_register("rezipe.emptyfilter", 'Rezipe\EmptyFilter') or die("Failed to register filter");

class Crc32Filter extends \php_user_filter {
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

class ZipdecryptoFilter extends \php_user_filter {
	function filter($in, $out, &$consumed, $closing) {
		$zc = $this->params["zc"];
		$crc32 = $zc->get_crc32();
		$de = $this->params["de"];
		while ($bucket = stream_bucket_make_writeable($in)) {
			#$consumed += $bucket->datalen;
			$buf = $bucket->data;
			if (!$zc->has_encryption_header()) {
				$decrypted = $zc->decrypt_header(substr($buf, 0, 12));
				if (ord($decrypted[11]) !== (($crc32 >> 24) & 0xff)) { //CRCエラー
					$de->log("BAD EncryptionHeader:".bin2hex($decrypted)." expects: __" . dechex(($crc32 >> 24) & 0xff), "E");
					return PSFS_ERR_FATAL;
				}
				$de->log("Hdr:" . bin2hex(substr($buf, 0, 12)) . "->" . bin2hex($decrypted), "D");
				$buf = substr($buf, 12);
			}
			$bucket->data = $zc->update($buf, false);
			$de->log("Dat:" . bin2hex(substr($buf, 0, 8)) . "->" . bin2hex(substr($bucket->data, 0, 8)) . " len:".strlen($bucket->data), "D");
			$consumed += strlen($bucket->data);
			stream_bucket_append($out, $bucket);
		}
		return PSFS_PASS_ON;
	}
}
stream_filter_register("rezipe.zipdecryptofilter", 'Rezipe\ZipdecryptoFilter') or die("Failed to register filter");


class DataExtracter {
	private $zipfh;
	private $data;
	public $option;
	public $zlib_params;
	public $crc32_params;
	public $zipdecrypto_params;
	public $buflen;
	private $zlib_filter;
	private $crc32_filter;
	private $zipdecrypto_filter;
	private $empty_filter;
	private $hasher;
	private $crc32;
	public $logs;
	
	function __construct() {
		$this->zipfh = null;
		$this->data = null;
		$this->zlib_params = array('level' => -1, 'window' => -15, 'memory' => 9);
		$this->crc32_params = array("hasher" => null);
		$this->zipdecrypto_params = array("zc" => null, "de" => null);
		$this->buflen = 32*1024;
		$this->crc32 = null;
		$this->hasher = null;
		$this->logs = array("D" => array(), "I" => array(), "W" => array(), "E" => array());
	}
	
	function get_crc32($pack = "") {
		if (!$this->crc32) {$this->set_crc32();}
		$crc32 = $this->crc32;
		if ($pack) {
			$crc32 = unpack($pack, $crc32)[1];
		}
		return $crc32;
	}
	
	function log($msg, $level = 'I') {
		$this->logs[$level[0]][] = $msg;
	}
	
	function run($opt = null) {
		if (!$opt) {$opt = array();}
		$opt = $opt + $this->option;
		$mem = fopen("php://memory", "wb");
		$to_write = $opt["zlib"] || $opt["crc32"];
		if (is_string($opt["zipdecrypto"]) && is_int($opt["crc32"])) {
			$this->set_zipdecrypto_filter($mem, $opt["zipdecrypto"], $opt["crc32"]);
		}
		if ($opt["zlib"]) {$this->set_zlib_filter($mem);}
		if ($opt["crc32"]) {$this->set_crc32_filter($mem, $this->hasher);}
		$this->set_empty_filter($mem);
		if ($this->data) {
			if ($to_write) {fwrite($mem, $this->data);}
		} else {
			stream_copy_to_stream($this->zipfh, $mem, $opt['compsize'], $opt['offset']);
/*
			fseek($this->zipfh, $opt['offset']);
			$len = $this->buflen;
			$unread = $opt['compsize'];
			while($unread > 0) {
				if ($unread < $len) {$len = $unread;}
				$unread -= $len;
				fwrite($mem, fread($this->zipfh, $len));
			}
*/
		}
		fclose($mem);
		if ($opt["crc32"]) {$this->set_crc32();}
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
	
	function set_zipdecrypto_filter($io, $password, $crc32) {
		$zc = new ZipCrypto();
		$zc->set_password($password);
		$zc->set_crc32($crc32);
		$this->zipdecrypto_params["zc"] = $zc;
		$this->zipdecrypto_params["de"] = $this;
		$this->zipdecrypto_filter = stream_filter_append($io, "rezipe.zipdecryptofilter",
				STREAM_FILTER_WRITE, $this->zipdecrypto_params);
		
	}
	
	function set_zlib_filter($io) {
		$this->zlib_filter = stream_filter_append($io, 'zlib.inflate',
				STREAM_FILTER_WRITE, $this->zlib_params);
	}
	
	public static function extract($opt = null) {
		$my = static::init($opt);
		$my->run();
		return $my;
	}
	
	public static function init($opt = null) {
		if (!$opt) {$opt = array();}
		$my = new static();
		$opt = $opt + array("input" => null, "data" => false,
				"offset" => 0, "compsize" => null, "zlib" => false,
				"crc32" => false, "buffer" => null,
				"zipdecrypto" => null);
		$my->option = $opt;
		if ($opt["input"]) {$my->zipfh = $opt["input"];}
		if ($opt["data"]) {$my->data = $opt["data"];}
		if ($opt["crc32"]) {$my->hasher = hash_init('crc32b');}
		if ($opt["buffer"]) {$my->buflen = $opt["buffer"];}
		return $my;
	}
}

if (isset($argv) && stripos($argv[0], basename(__FILE__)) !== FALSE) {
	if (!isset($argv[1])) {
		echo "Usage: php ${argv[0]} ZIP_FILE";
		return;
	}
	$params = array('zipfile' => $argv[1]);
	$opts = array(
		"--check-crc32" => array("type" => "boolean", "member" => "check_crc32"),
		"--password" => array("type" => "string", "member" => "password")
	);
	for($i=2; $i<count($argv); $i++) {
		if (!strpos($argv[$i], '=')) {continue;}
		list($op, $val) = explode("=", $argv[$i]);
		if (!isset($opts[$op])) {continue;}
		settype($val, $opts[$op]["type"]);
		$params[$op] = array($opts[$op]["member"], $val);
	}
	p($params);
	$parser = new ZipParser($params['zipfile']);
	if (isset($params['--check-crc32'])) {$parser->check_crc32 = $params['--check-crc32'][1];}
	if (isset($params['--password'])) {$parser->password = $params['--password'][1];}
	
	$result = $parser->parse();
	echo "\n======== RESULT ========\n";
	p($result);
	echo "\n";
	if (count($result['errors']) === 0) {
		echo "OK\n";
	} else {
		echo "!! Invalid zip format !!\n";
		echo "  " . count($result['errors']) . " errors\n";
		foreach($result['errors'] as $err) {
			echo $err . "\n";
		}
	}
}
