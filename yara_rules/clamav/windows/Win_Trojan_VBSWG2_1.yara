rule Win_Trojan_VBSWG2_1
{
strings:
	$a0 = { 6d7367626f782022214023352140237021402331214023642140233321402379214023232323204861707079204675636b696e672056616c656e74696e65202e2e2e21212120232323214023352140237021402331214023642140233321402379214023222c31302c2256616c656e74696e6544617922 }

condition:
	$a0
}

        