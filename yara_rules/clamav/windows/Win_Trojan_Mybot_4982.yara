rule Win_Trojan_Mybot_4982
{
strings:
	$a0 = { c8976679479b7f5c429220774d1a39af1a131fadb36ff562c066425594f3ae41b48053b74bcfa709860f71af3bc74fcc2a84256ae5ff34d6a278df6a4fadf61ac4fda8ffaa9295511f4d5c2c656c073c0df711ce3d2e613989120a450e11823ac32309c5f22bc8e33793e5a35cd1731faab48b4dc0c8739b567fb0bc8919d4edc543305a6e85bf2ed85b84ab5976bef947f80a182415 }

condition:
	$a0
}

        