rule Win_Trojan_VGEN_504
{
strings:
	$a0 = { 900640900efb1f4840bd210790be30014090409080347748404640fb404d75f4fb48489090fb9040fbfbfb40404890 }

condition:
	$a0
}

        
