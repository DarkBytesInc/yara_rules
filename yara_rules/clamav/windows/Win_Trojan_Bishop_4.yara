rule Win_Trojan_Bishop_4
{
strings:
	$a0 = { 49534b20464f4f4c202121210a2f43203239612e6578659a000051029a0d00ef015589e5b80003 }

condition:
	$a0
}

        
