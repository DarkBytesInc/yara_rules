rule Win_Trojan_Mybot_8491
{
strings:
	$a0 = { 611b7cb088aa823e546fa581d2df13aed67b2a1c5691213d387495f4ab20616fbc42e964600a49273c1d2f8c7492fd44e673dbf9a8d7eddcf320e5f143ab1724c517a4ed9e8f082b8a0da6bedb33e2f947d31249b4 }

condition:
	$a0
}

        
