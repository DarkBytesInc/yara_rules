rule Win_Trojan_Small_3609
{
strings:
	$a0 = { e8000000005a81c20b0b00008d8a1c0500005281320df0ad0b83c20439ca7ef389ca8b4204290283ea043b14247df3c3 }

condition:
	$a0
}

        
