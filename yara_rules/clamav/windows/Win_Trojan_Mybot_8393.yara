rule Win_Trojan_Mybot_8393
{
strings:
	$a0 = { f273f9e6d4043a6ab53c0c1e00ba62a177c3b05673a09333c8d4b24a1f8b0f2b8b091b6bddbcb4f733c945450058201620982baea6036a027f2d15ac74233ddf929d7dd528ab8b589fb9c1f29b77a8ae860ebef91a }

condition:
	$a0
}

        
