rule Win_Trojan_Small_3240
{
strings:
	$a0 = { 5268f38e47d7aaea5f54eece47e3456f370daececc1d9ad30710678a634c4eb25a50ee470b348e46033486777a10eece74d063b26379679a63741d65ca5ccacaca44cad6164288652d1084ce2d5484ceed7a }

condition:
	$a0
}

        
