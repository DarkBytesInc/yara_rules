rule Win_Trojan_KF_2
{
strings:
	$a0 = { 8d962b06b907007304ea00b705e806047214e81400b44e8d963706b90700e8f5037203e80300 }

condition:
	$a0
}

        
