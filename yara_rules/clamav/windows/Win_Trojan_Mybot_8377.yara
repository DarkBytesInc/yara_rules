rule Win_Trojan_Mybot_8377
{
strings:
	$a0 = { b3ed83a2a58aa845295d229188ed308d3d408f8324e013adceacdaded67c3796ac91df8c9052addd4538381f3e2fd8bdb78b0f3bad14c602c7556a48ee1983364390c125cb8a279328f2e893ad30ac457a8aa9a51e }

condition:
	$a0
}

        
