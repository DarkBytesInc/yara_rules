rule Win_Trojan_Graftor_885
{
strings:
	$a0 = { 689041400068f036400064a100000000506489250000000083ec685356578965e833db895dfc6a02ff15cc40400059830d685e4000ff830d6c5e40 }

condition:
	$a0
}

        