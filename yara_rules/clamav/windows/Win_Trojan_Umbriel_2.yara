rule Win_Trojan_Umbriel_2
{
strings:
	$a0 = { 77696e6469722b225c77696e646f77732e636d64[0-60]73687574646f776e2d732d662d74333030 }

condition:
	$a0
}

        
