rule Win_Trojan_Vedetar_1
{
strings:
	$a0 = { 6e363d2020202073657420257661722e6d65737361676520200331345b0334ae200331305777572e44616e61526f676f7a2e476f2e526f20030334ae0331345d0f0331302044616e6120526f676f7a20566564657461200334504f524e4f033130203f3f }

condition:
	$a0
}

        