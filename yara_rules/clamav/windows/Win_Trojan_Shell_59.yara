rule Win_Trojan_Shell_59
{
strings:
	$a0 = { 2f2f7261772069726320636f6d6d616e6420666978656420627920746f777a616f }

condition:
	$a0
}

        
