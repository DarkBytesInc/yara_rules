rule Win_Trojan_Hackdef_6
{
strings:
	$a0 = { 6a63244440523a35312b27a110f1df21d028ec21fd004d005c4261736546288de435645c5c2e5c6ddafdc89f2a5c68786465662d726b313030 }

condition:
	$a0
}

        
