rule Win_Dropper_Agent_33406
{
strings:
	$a0 = { 68b83040006a00e8000002a46a0068800000006a036a006a01680000008068b8304000e8000003c2a338314000833d383140000075106a006a0068043040006a00e8000003b6 }

condition:
	$a0
}

        