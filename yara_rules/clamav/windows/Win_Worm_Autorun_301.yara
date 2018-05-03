rule Win_Worm_Autorun_301
{
strings:
	$a0 = { 6f70656e3d777363726970742e65786520766972757367756172642e766273 }

condition:
	$a0
}

        
