rule Win_Trojan_SdBot_3910
{
strings:
	$a0 = { e2996d0521b176f399a8ef0a2f2bd07c866bcea33e2c6e3c90ce97d9cbfc2d90db040df9df1d1ad7eb49fb66cd433cc04247cabfb474bc0ed1ae0dff1640e2845de6ff100896a18e97e4aef8fad3a042115c5659aa8dbbc9cef8dd3c }

condition:
	$a0
}

        
