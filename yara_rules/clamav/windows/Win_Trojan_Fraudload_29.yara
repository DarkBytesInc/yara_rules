rule Win_Trojan_Fraudload_29
{
strings:
	$a0 = { 4600000000000033000000006b6e4a00000069697a500058756500674d00007100004156006a477249786b31003669007700000078000000004600670072490078004b00380000736300004b0000000000000071 }

condition:
	$a0
}

        