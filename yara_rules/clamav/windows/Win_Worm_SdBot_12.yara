rule Win_Worm_SdBot_12
{
strings:
	$a0 = { 410989c843681477048d711417c74c28ce7af99ac4ddae987ba071d710811304ff12440d5c0f4ba3b0f21648122c3d07 }

condition:
	$a0
}

        
