rule Win_Trojan_Clicker_90
{
strings:
	$a0 = { 6b6579776f72645f646f756d695f75702e6578650000000025730000687474703a2f2f }

condition:
	$a0
}

        
