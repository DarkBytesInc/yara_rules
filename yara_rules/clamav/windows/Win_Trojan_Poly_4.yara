rule Win_Trojan_Poly_4
{
strings:
	$a0 = { 7375622066696c65696e666563746f72312064696d2076616c75652076616c75653d6c656674287265672e7370656369616c666f6c646572732870636d696c642822 }

condition:
	$a0
}

        