rule Win_Trojan_OptixPro_20
{
strings:
	$a0 = { 344f13dbeac5e18b8774d465e966c396f5f3652f1f7efd92e2cd7179a8d980d0cccd74dc61fae52d71d6cd822ec3c80cd5187a1de227c76aafdbb84a36ee4d825dc7bddd73b745996df5cbdc3deeb77aa5bf9e590654cf91315c27ffc906c70cb08ced895c4ebbed1b6f393b57d42bbc2fb2aceacdf47e38849650 }

condition:
	$a0
}

        
