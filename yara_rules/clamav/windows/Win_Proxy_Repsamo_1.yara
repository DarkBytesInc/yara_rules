rule Win_Proxy_Repsamo_1
{
strings:
	$a0 = { 721bb82c3500106a00505068c812001068c01200106a00ff1508110010 }

condition:
	$a0
}

        
