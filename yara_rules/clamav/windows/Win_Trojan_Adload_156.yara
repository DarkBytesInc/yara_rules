rule Win_Trojan_Adload_156
{
strings:
	$a0 = { e8abffffffcccccccccccccccccccccc8b4c24048b51048b095355568b74241c33c05733ce8b74241cbf200000008bff8bdac1eb058beac1e50433dd03da8be883e5038b2cae03e833dd03cb8bd9c1eb058be9c1e50433dd2d4786c8618be8c1ed0b83e5 }

condition:
	$a0
}

        
