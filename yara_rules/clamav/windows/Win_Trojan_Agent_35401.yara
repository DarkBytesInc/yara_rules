rule Win_Trojan_Agent_35401
{
strings:
	$a0 = { 558bec83c4f0b8246f4500e814004c5ca1b49445008b00e81404fc808b0d94954500a1b49445 }

condition:
	$a0
}

        
