rule Win_Trojan_Dialer_760
{
strings:
	$a0 = { 7474726f206f726520636c696363616e646f20717569206f20737520454e5452412e00414952002564004d65737300040000006d6f64656d006973646e00717269626564666cb40067626261 }

condition:
	$a0
}

        