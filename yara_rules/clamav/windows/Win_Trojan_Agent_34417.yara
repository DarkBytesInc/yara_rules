rule Win_Trojan_Agent_34417
{
strings:
	$a0 = { 558bec83c4f053b8e8984500e83fcffaff8b1d80b545008b03e8462cffff6aec8b038b403050e899d6faff0d80000000506aec8b038b403050e866d8faff8b0db8b645008b038b15108a4500e82b2cffff8b03c6405b008b03e89e2cffff5be8c4a9faff }

condition:
	$a0
}

        
