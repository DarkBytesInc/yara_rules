rule Win_Trojan_Small_3905
{
strings:
	$a0 = { 8b31daa9cc1b11811960aaa8e26bdbef8b3156aacc1bdb801023869817140a5d90a0850e947ae4f5e79e4aa94fa1730d9c70f0988b31d6a9cc1bd697a16b96d88ca6d5a81770aac4f61bf098f61ef098f61bf0e8dd6d85ae482d }

condition:
	$a0
}

        
