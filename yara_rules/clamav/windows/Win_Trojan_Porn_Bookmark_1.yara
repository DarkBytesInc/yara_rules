rule Win_Trojan_Porn_Bookmark_1
{
strings:
	$a0 = { 5b496e7465726e657453686f72746375745d[1-2]55524c3d687474703a2f2f[1-10]706f726e }

condition:
	$a0
}

        
