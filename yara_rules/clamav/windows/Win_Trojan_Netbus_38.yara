rule Win_Trojan_Netbus_38
{
strings:
	$a0 = { 4d50c116e6ed2cf1a8699331de0433c6a9a404e7b4eeb987cee74f6ec3e1492991721fa7a355dc2eccbc8e6e53a3084225fed98a004c84c144f3cf9ae04cf3c37d0b12aeae893a3e396d159ce712a34d37ede0e5f118f3906033c9670bbc61472c9aabb4 }

condition:
	$a0
}

        
