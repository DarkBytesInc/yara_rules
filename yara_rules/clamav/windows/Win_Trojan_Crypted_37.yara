rule Win_Trojan_Crypted_37
{
strings:
	$a0 = { 5533e533e55de9f5 }
	$a1 = { 558bec83ec48565764a1300000008b70088975e08b400c8b401c8b008b40088945e464a11800000083603400c745f87f }

condition:
	$a0 and $a1
}

        
