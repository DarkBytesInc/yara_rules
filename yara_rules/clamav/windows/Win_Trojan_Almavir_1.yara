rule Win_Trojan_Almavir_1
{
strings:
	$a0 = { eb0d00000000be0a302a2e636f6d00b42ccd21881604018cc88ec08bd88edbc70602010000be0f018b0e060181f9b41476158cc80500108ec033ffbe0f01f3a48b3e0601e9 }

condition:
	$a0
}

        
