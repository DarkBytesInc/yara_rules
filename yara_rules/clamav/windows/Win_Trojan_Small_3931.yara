rule Win_Trojan_Small_3931
{
strings:
	$a0 = { 71be2a3ac66b7e69ba783ac530a782b553af6ab981a339692f503cc53057952fb5be2a3accea9eb7005339b1701f7b7a45ffe77fb1ff022945af4ac53057ad7fb9ab6a3a4550bc03185b1e18c4d29ef245af6a4e5c2e17ced1ae6a3a4a2b443945afad7fb5ae6a3a4546 }

condition:
	$a0
}

        
