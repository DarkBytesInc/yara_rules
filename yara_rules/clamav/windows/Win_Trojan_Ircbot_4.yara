rule Win_Trojan_Ircbot_4
{
strings:
	$a0 = { 633a5c57696e646f77735c54656d705c6d6972632e6578650d0a633a5c57696e646f77735c54656d705c6c6f6c2e6c6e6b }

condition:
	$a0
}

        
