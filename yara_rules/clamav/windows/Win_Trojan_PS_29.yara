rule Win_Trojan_PS_29
{
strings:
	$a0 = { 1301bbaa00814600000045454b75f6e800005d81ed16018db6c40101010157a5a4c686c702011acd8d969c02210e8d }

condition:
	$a0
}

        
