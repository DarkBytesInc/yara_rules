rule Win_Trojan_Spambot_234
{
strings:
	$a0 = { c2572f2993743ee7afffffffaf16a1bcc4d4edbad140b19ab5f22a183b77b5a9cfaf37f304ffffffffff63a3b400e30d803c4f2df0d8a24199f8e2ceb82b8af5db90f5f7893d7ed80bf0ffffffffe96d8840c40fc5ab2229a429e714bf14b5471622256e238a2c7ebb7dcf854191 }

condition:
	$a0
}

        
