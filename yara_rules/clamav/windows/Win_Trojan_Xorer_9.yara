rule Win_Trojan_Xorer_9
{
strings:
	$a0 = { 333630616e746900333630736166650061727000617667 }
	$a1 = { 2536312537332537[0-20]584f52 }

condition:
	$a0 and $a1
}

        
