rule Osx_Trojan_MSShellcode_105
{
strings:
	$a0 = { b8610000026a025f6a015e4831d20f054989c54889c7b8620000024831f65648be0002115c0a074dba564889e66a105a0f054c89efb81d0000024831c9514889 }

condition:
	$a0
}

        