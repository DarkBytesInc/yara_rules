rule Win_Trojan_Mybot_208
{
strings:
	$a0 = { d1ca080a3d9025289966b608e6e92ba43af476663a99f5b4ae115a8dbe110d258ae5f54e656c6360a55868ad4c356263c5637664495a77a7abd101794e0d2b308c4b5b8a6294aa2510e61fbb482a8af11c17995addd8cdda601249afb9e54695f5e962c187df33c79e360588c45f98c7c6eb7057fd85f16319a1d30388e7eb492ec5fb44ff }

condition:
	$a0
}

        