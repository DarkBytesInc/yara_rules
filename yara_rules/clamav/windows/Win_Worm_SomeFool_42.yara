rule Win_Worm_SomeFool_42
{
strings:
	$a0 = { 47edc547bf82754b5f70aae1e8efb3c4ad14eeefa0a7326b3f023225e31503d8e25b4febb7d32a02eb71cd9d12f9edf36365f7ea8c16ee88255f147559229a870f4f7770301676b3a2ba7d8bead7bb6a }

condition:
	$a0
}

        
