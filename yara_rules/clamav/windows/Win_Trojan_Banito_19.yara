rule Win_Trojan_Banito_19
{
strings:
	$a0 = { 005d40a2bff46ff0ee802ce8e6e4e6f01fdce0d226c0d2fef3fa224adf84702f61b138728b54f93b5a47198e32660a2d4840433fb9b1c9874756cf2afcd7490f98f13689ea0cc9770f5c0e1f5865cb8de90cfafdce04177f9b3a0814c5fae7eb58775aae93321a2da705dfe73ef06bbaedcbe0baaddd5ecffb903f3397 }

condition:
	$a0
}

        
