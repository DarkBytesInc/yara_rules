rule Win_Worm_SomeFool_5
{
strings:
	$a0 = { eca9865b573bf7ba0c99c8c0a80a1bf55dcd2e1e756e61e0ffd2338028744b2c4fb64debaca3ecb9ae60c0b5b8b3086edacdc3e1e1d40ba107051bfd78d5a675af9c61f4ee37cb2f6e200c3b8b70425b }

condition:
	$a0
}

        
