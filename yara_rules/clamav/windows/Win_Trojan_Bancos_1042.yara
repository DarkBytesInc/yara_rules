rule Win_Trojan_Bancos_1042
{
strings:
	$a0 = { 1974bb00e6d7d3c282ad38612f42206f6b63ad82bd43a6ca0fa28708d5a23715dd89b6886e66c61f131080eff8ab0b363bedd1e92765908fff60fc0a6ac910499a46e74189bec5dddc2c14514db96cfbcccd986b763c90dd }

condition:
	$a0
}

        
