rule Win_Worm_Autorun_401
{
strings:
	$a0 = { e8d8feffff2bc61da71bcb4b13c0c30c7bf7ec669af6f18e1b2014678dc07e }

condition:
	$a0
}

        
