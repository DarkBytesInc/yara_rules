rule Win_Trojan_Mybot_293
{
strings:
	$a0 = { 151a201a005b25735d3a204578706c6f69230a5c49500b0325732e6c0609687474703a2f2f25733a257355000008005000400007626561676c6531003011bc0d05c3f5285c }

condition:
	$a0
}

        