rule Unix_Tool_13301_1
{
strings:
	$a0 = { 7c3f0b787ca52a794240fff97f0802a63b18013498b8fefb3878fef49061fff83881fff890a1fffc3bc001607fc02e7044deadf2 }

condition:
	$a0
}

        
