rule Win_Trojan_Fraudload_16
{
strings:
	$a0 = { 34cc398177f67d7ea2b1ffffff2114f3ffffa5c763bb452234a20919ffffff1b49b9fefffffebcfa5a2dfeffffddf9aef0ffff7d592dfeffffff01bdf0ffff05498dfeffffdd09edf0ffff0549f1ffffffc5c2f535f349800244e080d1f8f48a49a9eaff }

condition:
	$a0
}

        
