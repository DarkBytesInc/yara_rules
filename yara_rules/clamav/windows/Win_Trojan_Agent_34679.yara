rule Win_Trojan_Agent_34679
{
strings:
	$a0 = { 56525ac1cf05c1c70533f7578b74240483c408e9b16101006081eb0694402881ee960a0c646100 }

condition:
	$a0
}

        
