rule Win_Trojan_Schizo_3
{
strings:
	$a0 = { 0c509a15022700b008509a59022700bf52011e57bf05010e5731c0509a260689009aa9058900 }

condition:
	$a0
}

        
