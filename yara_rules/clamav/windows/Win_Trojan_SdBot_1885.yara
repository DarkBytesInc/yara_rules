rule Win_Trojan_SdBot_1885
{
strings:
	$a0 = { cfa29701c4354d117dae830c06568199d72ea9bfc65c0ac1c7eb513287ceb5b80567da4cec7c02c7fd8c530ba58c67985c7f7d255b929dcbb6d25436a3d6895654ad34ceb98212988b3bd282de1fe97720853f3ccfa24d8b0c5a7d70a6aae7e38a8b }

condition:
	$a0
}

        
