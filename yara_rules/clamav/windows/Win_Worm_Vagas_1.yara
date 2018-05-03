rule Win_Worm_Vagas_1
{
strings:
	$a0 = { 8b1d80104a006844974a008d45bc50ffd38d45bc508d85b8feffff50ff153c104a00ff359c154a008d45bc50ffd38d85b8feffff6874914a0050ff15ac104a0085c05959 }

condition:
	$a0
}

        
