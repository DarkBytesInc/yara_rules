rule Win_Trojan_E_40
{
strings:
	$a0 = { ffffffe9c20200008b47fb0d002020203d2e6578650f85af0200008d85460a42006a006a006a036a006a0068000000c050ff95d60642008985b0074200400f847a020000488d95e00742008d8dac0742006a00516a405250ff95da0642006681bde00742004d5a0f855102000080bdf8074200400f82440200008b95 }

condition:
	$a0
}

        