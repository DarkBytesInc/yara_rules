rule Win_Trojan_Delf_1578
{
strings:
	$a0 = { 683c3540008d44240450e834eaffff54e83eeaffff54e838eaffff54e83aeaffff54e82ceaffff54e82eeaffff8bc4e84feeffff81c404010000c3766572636c7369642e6578650000000051e86aeaffffa3f0564000e868eaffffa3f45640 }

condition:
	$a0
}

        
