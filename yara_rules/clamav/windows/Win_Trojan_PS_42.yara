rule Win_Trojan_PS_42
{
strings:
	$a0 = { 817600210c4545e2f6c90c21540c1f2187c91227b46048ec2d1c5f71784080e14c0c0e2182f98f0f1e215da222220c }

condition:
	$a0
}

        
