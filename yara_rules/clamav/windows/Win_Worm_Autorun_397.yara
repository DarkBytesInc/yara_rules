rule Win_Worm_Autorun_397
{
strings:
	$a0 = { 6f70656e3d6963655c666972655c747261796d67722e657865 }

condition:
	$a0
}

        
