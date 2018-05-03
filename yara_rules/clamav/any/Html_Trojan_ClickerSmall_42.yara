rule Html_Trojan_ClickerSmall_42
{
strings:
	$a0 = { 38312e372f636f6e6e6563742e7068703f6469643d4f442d53544e44383036000043616e27742063 }

condition:
	$a0
}

        
