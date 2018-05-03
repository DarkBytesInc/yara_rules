rule Html_Trojan_Concon_8
{
strings:
	$a0 = { 626f6479206261636b67726f756e643d22633a5c636f6e5c636f6e22 }

condition:
	$a0
}

        
