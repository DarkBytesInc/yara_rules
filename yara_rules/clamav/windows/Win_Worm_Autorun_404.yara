rule Win_Worm_Autorun_404
{
strings:
	$a0 = { 526561644d652e657865 }
	$a1 = { 696f6e5c52756e[0-12]2f73696c656e74 }
	$a2 = { 616374696f6e3d4f70656e204472697665 }

condition:
	$a0 and $a1 and $a2
}

        
