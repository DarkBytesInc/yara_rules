rule Win_Trojan_Spambot_183
{
strings:
	$a0 = { 8b8f39ef2db310cdd6d2e2a3b9bc9aabc67945e845ffffffff510b14e13b7baf66f009ec8c1fc45ea35509ab23526e154a009d3a248af6f170ffffffff9541c1de9cb030c486abbde13d056eabd091d3a017f6d05fd376b43d91fff378ffffffff8a6b7e95448ad8ad1d7c126986 }

condition:
	$a0
}

        
