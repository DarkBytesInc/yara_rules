rule Win_Trojan_Agent_34910
{
strings:
	$a0 = { da6a2da8f26e2738ec786f2e548b26d6a3aab429548b2e7ae9a35b40efb4034cf47f27210db47d3973ae27280f86425be7a25948f8b84247ac9f48d689d0da5dc0be4a21d0ce7f4ce1be59d6f3aad64cac815f4683b5585b8592 }

condition:
	$a0
}

        
