rule Win_Trojan_Status_1
{
strings:
	$a0 = { 7472797b74656d705661723d77696e646f772e6469616c6f67417267756d656e74732e6c6f636174696f6e2e687265663b7d63617463682865297b77696e646f772e636c6f736528293b7d }
	$a1 = { 73657454696d656f75742822436865636b5374617475732829222c313030293b }

condition:
	$a0 and $a1
}

        