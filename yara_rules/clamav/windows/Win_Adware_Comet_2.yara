rule Win_Adware_Comet_2
{
strings:
	$a0 = { 25535c2a2e2a0000444d5f536572766572000000536f6674776172655c4d6963726f736f66745c57696e646f77735c43757272656e7456657273696f6e5c000063757272656e744c6f670000536f6674776172655c436f6d65742053797374656d735c444d0000003200000025004100 }

condition:
	$a0
}

        