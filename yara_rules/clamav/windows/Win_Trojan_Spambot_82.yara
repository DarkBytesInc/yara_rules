rule Win_Trojan_Spambot_82
{
strings:
	$a0 = { b8761dfa874c884525f26add7eb7ffffffffa2757b33e5b857b79dea9443eaa3c0c707b248063075a2aa77d57df1412c7a6affffffff2737734010c6405da031f4350bb2f60839f06ff712c3277f971a74916ca86f87ffffffffac516c0f0d0470d41bb4b34efd105c567ddf52be }

condition:
	$a0
}

        
