rule Win_Trojan_Mybot_8335
{
strings:
	$a0 = { 983295737345cd3930f6531badbce9f614b4185fca173e909794a8f2983a8deda85fbada881ea729862a94cf14cce6c7d2ccb1854abe80d1322d7b1d24f10a61b5f6aa8cc211e2e9ed3789e9b42a9312 }

condition:
	$a0
}

        
