rule Win_Trojan_Agent_32905
{
strings:
	$a0 = { a3cad1638fa0e1a3e31a6b6d6b5bbd1d64974c25d53f9552ccbf7e19f243659eaeb18ff2807945e40b3008f65da0dd788d504e28319c03b6f76cc4f7539305dc7840928c477f4c777472427cadeb }

condition:
	$a0
}

        
