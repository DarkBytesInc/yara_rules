rule Win_Trojan_Spambot_77
{
strings:
	$a0 = { 9b00cafb619d7ffffff0ffd849ade46705798b45b9b6cb29f8c0e715449d55b0d28e6393d3ffabffffda2b84b514e1e4b35f508678d286da4ac02333a40118981f11fcffffffff75747b984c9260e2d378745e9d9c12ef9f15530c1f0ac0639a6dec50e9adc3fcff4b53ff7c6120 }

condition:
	$a0
}

        
