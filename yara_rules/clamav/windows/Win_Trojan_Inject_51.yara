rule Win_Trojan_Inject_51
{
strings:
	$a0 = { 6801504000e801000000c3c31cb39db577753083006244f2c989a6450834ba02f62247939d07fc27a6 }

condition:
	$a0
}

        
