rule Win_Trojan_Fakealert_89
{
strings:
	$a0 = { 37aedb495ebf1db243b3acd63cb6d2c83d5f9aea2691369bd3f81e513fef69f1bcb9573c3de2cefabc307a35e28a96b22f6704ab327da3febcdb26d8a37b92493ceef1e0a86311d5e7eb33595816bdce3ac5dd1c36a26f1a55bc17b0b002d71ce34d683c }

condition:
	$a0
}

        
