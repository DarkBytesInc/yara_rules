rule Win_Trojan_Beer_3
{
strings:
	$a0 = { 1e06505351525657559ce8b5ffe99a04909090fa903d003d740f3d023d740a80fc5674053d004b75231e0650535152 }

condition:
	$a0
}

        
