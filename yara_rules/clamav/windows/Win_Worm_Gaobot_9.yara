rule Win_Worm_Gaobot_9
{
strings:
	$a0 = { 524343490000000049545155000000005254504100000000434b4e49000000004956505247204d53203a257372657363796f7720257375200a00210d434b4b49000000000000203a0000210049565052 }

condition:
	$a0
}

        