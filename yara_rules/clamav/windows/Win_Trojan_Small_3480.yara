rule Win_Trojan_Small_3480
{
strings:
	$a0 = { 6fd7c22efc4640c934a11f0c739dea67a2eb1ff91e19e3b6148769e81914e70b2614cac7d57db0f8c69bbdb541a31683e1d1fb6f8d4f59fc243187286d92c55cdb54a5aaa990fc794d92b945735f }

condition:
	$a0
}

        
