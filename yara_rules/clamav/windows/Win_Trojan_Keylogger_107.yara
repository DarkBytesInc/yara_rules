rule Win_Trojan_Keylogger_107
{
strings:
	$a0 = { 3c0049006e007400650072006e00650074002000500061007300730077006f007200640073003e0000000000260000003c004f00750074004c006f006f006b002000500061007300730077006f007200640073003e000000260000003c004400690061006c0055007000200043006f006e006e0065006300740069006f006e003e0000001a0000003c00550052004c00200048006900730074006f00720079003e000000120000003c004b00450059004c004f00470047003e }

condition:
	$a0
}

        