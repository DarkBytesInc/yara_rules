rule Win_Trojan_NeoCon_2
{
strings:
	$a0 = { b70c202d204e656f436f6e74906c5265642053657276dd767fbb020019aa42002201233e366c74033604cef2a4 }

condition:
	$a0
}

        
