rule Unix_Trojan_MSShellcode_41
{
strings:
	$a0 = { 31dbf7e3b0664352536a0289e1cd80525089e1b066b304cd80b06643cd8059936a3f58cd804979f8b00b682f2f7368682f62696e89e341cd80 }

condition:
	$a0
}

        
