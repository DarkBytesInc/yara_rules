rule Win_Worm_Autorun_307
{
strings:
	$a0 = { 5368656c6c5c4578706c6f72655c436f6d6d616e643d626f6f742e657865 }

condition:
	$a0
}

        
