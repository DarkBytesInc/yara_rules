rule Win_Trojan_Jaja_1
{
strings:
	$a0 = { 6f0267c2806903464e24076a0e3a566963746f725769646a616a61126a14476c6f62616c3a566963746f725769646a616a61126c0100646f0267c2806903464e24076a0e3a46696c6554656d706c61746573126a14476c6f62616c3a46696c6554656d706c61746573126c }

condition:
	$a0
}

        