rule Win_Trojan_BO2K_10
{
strings:
	$a0 = { 899010bf001083c2f183e21f89880cbc0010899014bf001083c2f183e21f81c1a1ebd96e899018bf0010898810bc0010 }

condition:
	$a0
}

        
