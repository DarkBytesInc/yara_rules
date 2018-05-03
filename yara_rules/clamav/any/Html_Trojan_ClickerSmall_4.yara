rule Html_Trojan_ClickerSmall_4
{
strings:
	$a0 = { 65735c55524c5a2e747874000000ffffffff06000000cacbc8cac0de0000ffffffff010000002d000000558bec81c4ccf8ffff5333c08985ccf8ffff33c0556865b4450064ff30648920e8eb76faffe80aeefaff83c4f8dd1c249b8d85ccf8ffffe8d4f9faff8b95 }

condition:
	$a0
}

        
