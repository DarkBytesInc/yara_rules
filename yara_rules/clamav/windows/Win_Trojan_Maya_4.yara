rule Win_Trojan_Maya_4
{
strings:
	$a0 = { 410003c5506a016a00b8f10e410003c550ffb5db0e41008b85ac0f4100ffd06a00b8000f410003c5506a006a148b85b40f4100ffd06a30b8380f410003c550b8110f410003c5506a008b85b00f4100ffd0c3546f20417061726e6120532e203a20466f726576657220696e206c6f7665207769746820796f75 }

condition:
	$a0
}

        