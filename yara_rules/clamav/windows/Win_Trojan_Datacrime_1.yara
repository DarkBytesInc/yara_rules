rule Win_Trojan_Datacrime_1
{
strings:
	$a0 = { 010183ee038bc63d00007503e9fe008dbcdb04bb0001b905008b05890783c30283c7024975f3b42acd212e8a84f0043ac67f0a2ec684f0040090eb0690 }

condition:
	$a0
}

        
