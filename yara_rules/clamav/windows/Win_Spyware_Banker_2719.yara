rule Win_Spyware_Banker_2719
{
strings:
	$a0 = { e3a41f1b16d53110225a95a6548c9e385315a3537c4c508015d8f5827314ba6685bc7c193faee2f597ac4230bc5baa07945514e4721fbd941ac9 }

condition:
	$a0
}

        
