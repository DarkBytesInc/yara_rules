rule Win_Dropper_Microjoin_6
{
strings:
	$a0 = { 648b38488bc8f2afaf8b1f6633db66813b4d5a740881eb00000100ebf1e878ffffff6800104000ff151310400093e867ffffff6807104000ff151310400093e856ffffff33edbb00144000be }

condition:
	$a0
}

        
