rule Win_Worm_Autorun_233
{
strings:
	$a0 = { 7368656c6c5c6f70656e5c636f6d6d616e643d72656379636c6572[0-46]5c69736533322e657865 }

condition:
	$a0
}

        
