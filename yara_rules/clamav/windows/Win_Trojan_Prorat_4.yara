rule Win_Trojan_Prorat_4
{
strings:
	$a0 = { d013420b141a08b1f5fa957e91b8f6007819d1211c8f866474ca547b601401240b86b81c345e927065ff1829ae1e433c884035ad10d42a4895fcc3b481019019f0714a387f0cfc8d434c71040490e6318ffc0e1aabb09f181043de701257c3909191442e135bb8fd7b846a7d0b7573f6857b2a40746a64616ec38b2348d536ae2e1d2790 }

condition:
	$a0
}

        