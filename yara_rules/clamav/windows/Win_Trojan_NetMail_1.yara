rule Win_Trojan_NetMail_1
{
strings:
	$a0 = { 70e92e672f20d0090760b00357c85f5946500500400940dbfc2ae4050018434f4445b8da90bb64cb06dcc49a954441926eb0cf5441581dfb1e82e0d6fcfc164f }

condition:
	$a0
}

        
