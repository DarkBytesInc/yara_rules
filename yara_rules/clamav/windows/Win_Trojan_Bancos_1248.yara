rule Win_Trojan_Bancos_1248
{
strings:
	$a0 = { 98160654a74c4ff40cf2da798de9dbced3f700023877f6a18a01dfe36f143a0c1c37db81090aa4186b2c511c0e4246006c7ad8b8b4ccb1d87ef4707ed8e4c8a7144b7348d3ea42dd55b369fd172784a1e7416182635960381c165a79f036ce3038442a7c328f84664d144d2a44d0054456deaced70839c4d34149d47ceb5310aef1fec }

condition:
	$a0
}

        