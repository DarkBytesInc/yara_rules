rule Html_Trojan_ClickerSmall_60
{
strings:
	$a0 = { 6f6b65235bf6ff722e636f6d2f676f2e706870231f7ea938f673686f77214e4f2f43524f4c4cdbf600d8074e7f07430474b1ad7dfb726f6c205032656c5c490c346e1af6baedb7610d47656f006920752179f72bc160dd4000742d0300ef210c }

condition:
	$a0
}

        