rule Win_Trojan_TheThing_6
{
strings:
	$a0 = { fbff0000ffffffff27000000744865207448696e6720312e3620636c69656e74202d20636f70796c656674205f426c61 }

condition:
	$a0
}

        
