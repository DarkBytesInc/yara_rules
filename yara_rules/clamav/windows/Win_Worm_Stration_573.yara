rule Win_Worm_Stration_573
{
strings:
	$a0 = { 83ec34b90c00000033c0535657be0c3040008d7c240cf3a566a58a5c040c80f3 }
	$a1 = { 83ec18a1683140008b0d6c3140008b15703140008944240866a174314000894c240c8a0d7631400066894424 }

condition:
	$a0 and $a1
}

        