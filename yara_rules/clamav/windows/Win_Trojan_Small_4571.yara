rule Win_Trojan_Small_4571
{
strings:
	$a0 = { 87d3e804000000f991894040eb048b3c26d74883ecfc87d35156be66b4123087342487ede805000000e9357f7d3e474f }

condition:
	$a0
}

        
