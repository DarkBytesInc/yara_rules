rule Win_Trojan_Hupigon_231
{
strings:
	$a0 = { 6c43531a22e4c149ade66e596960e8dc6893b804d3f2ae29ab80a1f2be2da3baf9d315dce06bb0dd905739bb12c07dc3a6bfd7bfaf3811196952382a474b3159879ed7f0f69105b82fd35120366f4141f65f252782cc8ccf3ee0354e4ddfde90b2170b6a7f9d9c875ef3326559da }

condition:
	$a0
}

        