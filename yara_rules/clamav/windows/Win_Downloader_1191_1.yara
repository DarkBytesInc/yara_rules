rule Win_Downloader_1191_1
{
strings:
	$a0 = { 9ec6ca2c97d22cc818af2900a2d1b8ee51458ae2b24d2d881779e0388994ab9f7409a3dbbdfee1e5b6d215a783f29b6c458849c75b38cd07b45eb3272fba0560e40efce667a50e5883270d4521caeae6eb69d805a75691b1444d6aee }

condition:
	$a0
}

        