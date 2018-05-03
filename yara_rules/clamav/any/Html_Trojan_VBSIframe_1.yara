rule Html_Trojan_VBSIframe_1
{
strings:
	$a0 = { 666f72613d31746f383030646f63 }
	$a1 = { 696672616d657372633d222b636872283334292b2274656c6e65743a2f2f }

condition:
	$a0 and $a1
}

        
