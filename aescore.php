<?php

function generateRandomString($length) {
	return substr(str_shuffle(str_repeat($x='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', ceil($length/strlen($x)) )),1,$length);
}

function encrypt_aes256($clear_text) {
	$iv = generateRandomString(16);
	$vkey = md5($iv);
	#$iv = str_pad($iv, 16, "\0");
	$encrypt_text = openssl_encrypt($clear_text, "AES-256-CBC", $vkey, OPENSSL_RAW_DATA, $iv);
	$data = base64_encode(gzcompress($iv.$encrypt_text));
	return $data;
}
function decrypt_aes256($data) {
	$data = gzuncompress(base64_decode($data));
	$iv = substr($data ,0 ,16);
	$vkey = md5($iv);
	#$iv = str_pad($iv, 16, "\0");
	$encrypt_text = substr($data ,16);
	$clear_text = openssl_decrypt($encrypt_text, "AES-256-CBC", $vkey, OPENSSL_RAW_DATA, $iv);
	return $clear_text;
}


/*
echo encrypt_aes256('aesencrypt');
echo decrypt_aes256(encrypt_aes256('aesencrypt'));
*/