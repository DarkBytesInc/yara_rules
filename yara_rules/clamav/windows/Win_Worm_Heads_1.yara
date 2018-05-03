rule Win_Worm_Heads_1
{
strings:
	$a0 = { 506894284000ffd68bd08d4dc0ffd750689c264000ffd68bd08d4dbcffd750689c264000ffd6 }

condition:
	$a0
}

        
