rule Win_Trojan_Delsys_14
{
strings:
	$a0 = { 67657466696c652822633a5c636f6e6669672e73797322292066322e64656c657465[0-33]5c77696e2e696e69 }

condition:
	$a0
}

        