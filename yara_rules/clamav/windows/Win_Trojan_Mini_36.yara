rule Win_Trojan_Mini_36
{
strings:
	$a0 = { cd2000000000e8b50b9a1010592a2e434f4d00582d030050bd01018b6e0081c50301fc8d7602bf0001b90600f3a4 }

condition:
	$a0
}

        
