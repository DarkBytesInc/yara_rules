rule Win_Trojan_Girls_2
{
strings:
	$a0 = { 0300903000000000000084475e4390405f3cb0386e358732ec2f212da52a1328cb257c2371219f1fcc1d2c1c90 }

condition:
	$a0
}

        
