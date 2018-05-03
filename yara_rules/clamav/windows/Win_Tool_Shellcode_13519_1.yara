rule Win_Tool_Shellcode_13519_1
{
strings:
	$a0 = { 5589e583ec18c745fc }
	$a1 = { c7442404e8030000c70424e80300008b45fcffd0c9c35589e583ec18c745fc }
	$a2 = { c7442404d0030000c70424010e00008b45fcffd0c9c3 }

condition:
	$a0 and $a1 and $a2
}

        
