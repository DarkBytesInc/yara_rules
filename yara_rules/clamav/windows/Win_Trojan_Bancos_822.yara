rule Win_Trojan_Bancos_822
{
strings:
	$a0 = { 8460f13bf7553be44147adc235f9439a9ea65462ab41e999df201b4c0bffee0059c57fa23693c5769da06848a8374510180424fce42bfb58b1d4bdae63ab9c5b09a907276834 }

condition:
	$a0
}

        
