rule Win_Trojan_WolfCheat_1
{
strings:
	$a0 = { 9a000080029a00007f029a4501b4019a76019a019a25083b009a000021005589e531c09adf048002bf96000e57b83f00 }

condition:
	$a0
}

        
