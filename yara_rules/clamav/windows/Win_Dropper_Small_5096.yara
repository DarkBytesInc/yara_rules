rule Win_Dropper_Small_5096
{
strings:
	$a0 = { ff1508104000ff75e0ffd66a05538d85ccfeffff5350685410400053ff15381040008d85ccfeffff506804010000ff1510104000e8bb0000006a0e }

condition:
	$a0
}

        
