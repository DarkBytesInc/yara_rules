rule Win_Trojan_VB_727
{
strings:
	$a0 = { 43003a005c00770069006e0064006f00770073005c007300610066006500740079[0-27]63003a005c }

condition:
	$a0
}

        