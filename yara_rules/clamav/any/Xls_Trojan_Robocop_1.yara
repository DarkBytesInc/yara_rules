rule Xls_Trojan_Robocop_1
{
strings:
	$a0 = { 4a0024006a010100270074016c732000540024008001010027008a01e00020007401a3000100050020008a01a3000300050004009400a3006400200094012800a001a300ff00200094012800aa01ad00020041332400b4010100424014010000ff00200094012100c001ec000200ad0011 }

condition:
	$a0
}

        