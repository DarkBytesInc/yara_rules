rule Win_Spyware_Assarbad_1
{
strings:
	$a0 = { 726b65796c6f67676572444c4c000c334d657373616765730000c753797374656d000081537973496e6974000c4b57696e646f7773 }

condition:
	$a0
}

        