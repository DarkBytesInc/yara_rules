rule Win_Trojan_Downloader_82
{
strings:
	$a0 = { 2e6372656174656f626a65637428227368[4-40]2e7368656c6c65786563757465[4-20]226f70656e22 }

condition:
	$a0
}

        
