rule Html_Trojan_Unicode23_94_38_102_1
{
strings:
	$a0 = { 320033002e00390034002e00330038002e003100300032 }

condition:
	$a0
}

        
