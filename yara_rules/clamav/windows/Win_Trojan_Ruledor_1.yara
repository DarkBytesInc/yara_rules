rule Win_Trojan_Ruledor_1
{
strings:
	$a0 = { 733d2564264354524c3d25640000687474703a2f2f7374617475732e636c727363682e636f6d2f6c6f616465722f696e7374616c6c2f0000000052657472696576696e67206c617465737420636f6e74726f6c207365742066726f6d2027 }

condition:
	$a0
}

        