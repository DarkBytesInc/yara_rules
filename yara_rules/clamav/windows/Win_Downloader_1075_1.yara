rule Win_Downloader_1075_1
{
strings:
	$a0 = { 75864439d02139b26d337a6349a77fc18ae1f2db7698529d9506824580ca30934e030b25e0646a2a7b6e7a1d7baa38eb5f3ce627d26c67bb24844d405ac36d66c1645ba88e891359a1d94af5252e1ce58760edc8f610d107581a5c28 }

condition:
	$a0
}

        