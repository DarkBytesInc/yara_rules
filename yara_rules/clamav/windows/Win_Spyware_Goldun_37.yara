rule Win_Spyware_Goldun_37
{
strings:
	$a0 = { 526172211a0700cf907300000d00[30-120]4d7357696e646f77735570646174652e657865 }

condition:
	$a0
}

        
