rule Win_Trojan_Bancos_727
{
strings:
	$a0 = { ad627322c2bec07009a41e77d36c75514927893f59ffcae5dddd4842e862cc1849ff714bc79765861dd643a71eaeb2e2c79dd7b9d5e201aa42182d528170341bf15bf50b066f03ff622cd906c55f4b9e }

condition:
	$a0
}

        
