rule Win_Worm_Warezov_1
{
strings:
	$a0 = { 832504400010508b44240c83e800744548742048740f487408081d00400010eb3a03dbeb36a00140 }

condition:
	$a0
}

        
