rule Win_Trojan_Fakecodec_6
{
strings:
	$a0 = { 77123195f0fdffff219514feffff1995e0fdffff218d80fdffff8b95d0feffff218518ffffff098518fdffff039544ffffff899500fdffff81ea001a00004a31d081c0bc00000085d273228b854cfeffff198528fdffff4021d00b854cfdffff4a0985c4 }

condition:
	$a0
}

        
