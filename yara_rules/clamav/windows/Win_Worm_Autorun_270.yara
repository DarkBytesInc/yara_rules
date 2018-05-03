rule Win_Worm_Autorun_270
{
strings:
	$a0 = { 7368656c6c5c6f70656e5c636f6d6d616e643d73797374656d5f63616368655c6c6f63616c652e657865 }

condition:
	$a0
}

        
