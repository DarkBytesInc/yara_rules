rule Win_Worm_Startion_3
{
strings:
	$a0 = { 66810d00304000700633c050556a025050680000010057ff150020400083f8ff0f85ce000000ff151420400083f802745b83f803745680442413fa83f80566c70500304000c80f7514 }

condition:
	$a0
}

        