rule Win_Trojan_Clicker_1
{
strings:
	$a0 = { f63137476c75787572751b3633ddec37a17465722d7811373520f6d67d7f746f702e6e750f346b65256c6577 }

condition:
	$a0
}

        
