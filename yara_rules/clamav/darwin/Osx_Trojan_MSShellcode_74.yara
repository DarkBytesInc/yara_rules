rule Osx_Trojan_MSShellcode_74
{
strings:
	$a0 = { b8610000026a025f6a015e4831d20f054889c7b8680000024831f656be0002115c564889e66a105a0f05b86a0000024831f648ffc64989fc0f05b81e0000024c }

condition:
	$a0
}

        