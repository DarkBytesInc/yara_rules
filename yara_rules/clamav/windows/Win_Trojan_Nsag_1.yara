rule Win_Trojan_Nsag_1
{
strings:
	$a0 = { 3b0000004f4c4545585400 }
	$a1 = { 400750ff5312618b400e03442404ffe058538bd850ff530f23c07405034317eb068d43b40343135bff }

condition:
	$a0 and $a1
}

        
