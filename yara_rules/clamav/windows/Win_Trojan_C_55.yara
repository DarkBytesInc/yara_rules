rule Win_Trojan_C_55
{
strings:
	$a0 = { 47139f06ff00c90120202020202042652041647669736564205468617420546869732050726f6772616d204973203130302520496c6c6567616c2e2020486f77657665722c2049747320496e74656e64656420507572706f736520497320546f2054616b65204f757420416c6c20 }

condition:
	$a0
}

        