rule Win_Worm_Inmota_1
{
strings:
	$a0 = { 592b1414141414fa0a0a0a0b0b0b0b0a0a0a0a0b0b0b0bef1f1f1ff7070707eb1b1b1b3b2b2b2bdc2c2c2c2c2c4b2a5e3b }
	$a1 = { 20202e70696600005c0000005f666e476174654031360000676174652e646c6c0000000072756e646c3133322e657865000000006e6c73002564000072756e646c313332000000006e6c73256400000077 }

condition:
	$a0 and $a1
}

        