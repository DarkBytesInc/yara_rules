rule Win_Trojan_Agent_32487
{
strings:
	$a0 = { 566a00ff15d423400056ff25b42240008a9428f4feffff8d8428f4feffff884d13e90000024355545d81ec08010000e90000 }

condition:
	$a0
}

        
