rule Unix_Trojan_Gafgyt_1
{
strings:
	$a0 = { 2f62696e2f62757379626f783b6563686f202d65202767617966677427 }

condition:
	$a0
}

        
