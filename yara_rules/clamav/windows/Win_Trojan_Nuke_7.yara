rule Win_Trojan_Nuke_7
{
strings:
	$a0 = { 4269746368536c61702076312e309affff00009affff00009affff00009affff00009affff00009affff00009affff00009affff00009affff00009affff00005589e531c09affff0000bf02000e57c43ef20c06579affff0000bfc000b8ffff5057bf9e0b1e57c43ef20c06579aff }

condition:
	$a0
}

        
