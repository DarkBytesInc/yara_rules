rule Win_Trojan_Dialer_737
{
strings:
	$a0 = { 617965722e0d0a0d0a5741524e494e473a204279207573696e67207468697320736f6674776172652c20796f7572206d6f64656d2077696c6c206469616c204120444f4d4553544943205052454d49554d2052415445204f5220494e5445 }

condition:
	$a0
}

        