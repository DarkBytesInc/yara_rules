rule Win_Trojan_Vundo_413
{
strings:
	$a0 = { 50eb1ae8d45eff46c96a4d90ffd2e9134f0000c9e9fd5a00006aeeffd2e8dc0200009080f09058e80afdffff565e90eb0a5fe8bd4fff465effd05290eb1c4c5a42e915f70000e8265bff46ccc3e84789ff46ffd4416ab1ffd643803da5540010019090eb }

condition:
	$a0
}

        
