rule Win_Trojan_Rukap_79
{
strings:
	$a0 = { ef3cc906ff59cd76becb343d90715e8eabfbb575023a26c89571bf30bb18683476743c1bfcb8f3e01edd43e806e035b497ed50a70b2c1b86d870569b19f49d2ebf4ba3eceb866d54562cd87c014171dcac7e670b1ae16191e821dbdbe0b6de7c24c52b26e4d404 }

condition:
	$a0
}

        
