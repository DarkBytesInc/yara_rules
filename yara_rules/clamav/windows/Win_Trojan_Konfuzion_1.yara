rule Win_Trojan_Konfuzion_1
{
strings:
	$a0 = { 65742056696374696d203d2046534f2e4f70656e5465787446696c652847657446696c654e616d652c20312c2046616c736529 }
	$a1 = { 436f6e74656e75746f203d2056696374696d2e52656164416c6c2829 }
	$a2 = { 56696374696d2e577269746528766972757329 }
	$a3 = { 56696374696d2e577269746528436f6e74656e75746f29 }

condition:
	$a0 and $a1 and $a2 and $a3
}

        