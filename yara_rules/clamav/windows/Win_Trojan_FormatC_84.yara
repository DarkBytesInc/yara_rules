rule Win_Trojan_FormatC_84
{
strings:
	$a0 = { 666f726d617420433a202f71202f6175746f746573743e6e756c0d0a63616c6c20433a5c57494e444f57535c }

condition:
	$a0
}

        
