rule Win_Trojan_Rootkit_51
{
strings:
	$a0 = { e7028d04408955e0c1e0023bc27d1553ff15442040008b4524c7009a0000c0e95e0600008b451c8b4d1883643b0400836510008d04c50800000003c803cf837d1c00894de8890c3b7e5feb038b4de88b551085d275138b55f4c7443b0c0700000003ca894c3b08eb358bcac1e1038d14 }

condition:
	$a0
}

        