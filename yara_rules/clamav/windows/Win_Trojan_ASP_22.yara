rule Win_Trojan_ASP_22
{
strings:
	$a0 = { 73637269707466696c6528222e222b6c2c732c302c6c2b2263726970742229 }
	$a1 = { 307836342c30783337 }

condition:
	$a0 and $a1
}

        
