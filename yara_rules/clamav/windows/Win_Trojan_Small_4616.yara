rule Win_Trojan_Small_4616
{
strings:
	$a0 = { 2e72656d6f766520633a5c636f6e6669672e737973[0-9]633a5c6175746f657865632e626174 }

condition:
	$a0
}

        
