rule Win_Trojan_VCL_34
{
strings:
	$a0 = { 5d81ed03011e060e1f0e07e8c1018db691018dbe8901a5a5a5a58d962a03e86101b82435cd21899e6f038c8671038d969c02b425cd210e078db6ea02b4 }

condition:
	$a0
}

        
