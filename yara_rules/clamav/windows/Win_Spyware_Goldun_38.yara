rule Win_Spyware_Goldun_38
{
strings:
	$a0 = { 526172211a0700cf907300000d00[30-120]666f746f2e6a70672020202020202020202020 }

condition:
	$a0
}

        
