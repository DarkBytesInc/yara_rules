rule Win_Adware_Comna_2
{
strings:
	$a0 = { 6f6e6e616d652e636f6d000000496e7374616c6c4170704d6f6e0000002e646c6c0000000052656c656173654170704d6f6e00000025735c25732025640000000044697361626c6500776b696d74780000696b77776e640000486561727462 }

condition:
	$a0
}

        