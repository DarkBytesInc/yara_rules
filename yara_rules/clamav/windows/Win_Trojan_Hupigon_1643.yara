rule Win_Trojan_Hupigon_1643
{
strings:
	$a0 = { c4e7e97884953b0e20ae8b1c0a8ce5ccc7ccca4b9c2cdf2468973ca1c9a7953dc457298210af1c9c1005c6e4bc747cdd486af2f0f02ca3249cfeb0003ac0547e21850a55842891a2f280f62617db603c459fbb9b279ecbef5fa6 }

condition:
	$a0
}

        
