rule Win_Trojan_Prodigy_2
{
strings:
	$a0 = { e90000e80000cc5d81ed06018db67f02bf0001a5a4c686cc0200b44732d28db68c02cd21b41a8d96cd02cd21b44eb90700fe8e85028d968502cd21fe8685027306e972 }

condition:
	$a0
}

        
