rule Win_Worm_Stration_690
{
strings:
	$a0 = { 998aaf3ec4b7133f866478b01ddc695ecf72e5dc93c5ca14e32f2eb79065c918404371ad0d42eca6c8671b6865eee7809bd13b62db04e7f18f8002e6193779f24c90723de4c55a87dcb114e03f4e28a2 }

condition:
	$a0
}

        
