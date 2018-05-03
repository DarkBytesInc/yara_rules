rule Win_Worm_Autorun_273
{
strings:
	$a0 = { 22737973636f6e66333222 }
	$a1 = { 2861736362286173637a6e616b312920616e6420323532292f34 }

condition:
	$a0 and $a1
}

        
