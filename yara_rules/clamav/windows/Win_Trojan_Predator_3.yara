rule Win_Trojan_Predator_3
{
strings:
	$a0 = { 8be5fbb430bb4d49cd213d4d497503e9af008cc8488ed8803e00005a75f1b86408b104d3e8405048d3e8d0e9d3e8401e33db8edb290613041f58290603008cc8 }

condition:
	$a0
}

        
