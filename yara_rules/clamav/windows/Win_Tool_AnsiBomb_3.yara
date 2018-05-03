rule Win_Tool_AnsiBomb_3
{
strings:
	$a0 = { b8640050b85a04509a770cbc0050b8010050b8ffff50b80200509a2602bc00b8620450b85400509a }

condition:
	$a0
}

        
