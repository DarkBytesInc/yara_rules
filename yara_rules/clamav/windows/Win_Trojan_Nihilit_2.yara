rule Win_Trojan_Nihilit_2
{
strings:
	$a0 = { 57696e33322e4e6968696c6974206279204e6563726f6e6f6d696b6f6e2f5a65726f47726176697479 }

condition:
	$a0
}

        
