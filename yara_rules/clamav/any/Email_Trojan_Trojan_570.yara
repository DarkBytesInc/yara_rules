rule Email_Trojan_Trojan_570
{
strings:
	$a0 = { 596f75207365656d20746f206e6576657220676f696e6720746f20717569742073757270726973696e672075732e }

condition:
	$a0
}

        