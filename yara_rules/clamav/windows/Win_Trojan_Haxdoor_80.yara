rule Win_Trojan_Haxdoor_80
{
strings:
	$a0 = { 3e65626179d14e901ac67e046669fced142e36d8d4f04239706179703164908f616c2e63dc4c72a686d4396c64d417 }

condition:
	$a0
}

        
