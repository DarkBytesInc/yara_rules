rule Win_Trojan_Rootkit_31
{
strings:
	$a0 = { 8bff558bec51518b4508568b700468a40401008d45f850ff150c0f01008d45f850ff15080f010085f6740756ff15040f01005ec9c20400cccccccccc }

condition:
	$a0
}

        
