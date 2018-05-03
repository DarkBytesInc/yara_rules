rule Doc_Trojan_Bleed_2
{
strings:
	$a0 = { 6a61636b79283829203d2022c4f2e3b7e4b7aab7d6f4e3fee1f2d3f8f4e2faf2f9e3adb7c4f2e3b7e3ffb7aab7e4b9c1d5c7e5f8fdf2f4e3b9c1d5d4f8fae7f8f9f2f9e3e4bfe3beb9d4f8f3f2daf8f3e2fbf222 }

condition:
	$a0
}

        
