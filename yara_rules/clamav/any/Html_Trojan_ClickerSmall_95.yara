rule Html_Trojan_ClickerSmall_95
{
strings:
	$a0 = { 6be770682a26f63f63311c7478ab250d3639389c2234f24d3594234332b13230ca1c433342d2c64431c6fbd7eb32ff574deffdcf51455cb53861954d75ce438a857a01 }

condition:
	$a0
}

        
