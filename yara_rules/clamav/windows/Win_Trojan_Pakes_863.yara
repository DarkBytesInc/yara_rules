rule Win_Trojan_Pakes_863
{
strings:
	$a0 = { bd324ece215ebc12e08869ee3a2a98573ded295dd91aeca73d052cd61c076e2c06f42fe3c62666712a1e6fc9ba1846e431456ce963526de70a5858c897e164299e022b033a05db57490094a5577c7df4405568650c936cff7da52f7bd625e8beb501d3de57a8ad9b0af879dcd3b24b5fbd49503e1f9c4683c68a67162906670107a04c40680a33c96f81f8ee }

condition:
	$a0
}

        