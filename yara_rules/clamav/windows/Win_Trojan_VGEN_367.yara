rule Win_Trojan_VGEN_367
{
strings:
	$a0 = { 515256571e06e8c0017353e811020e0732c0b94901bf4106fcf3aae83501b452e86f0253b430e869025fe874013c }

condition:
	$a0
}

        
