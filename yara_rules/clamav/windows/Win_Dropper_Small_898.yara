rule Win_Dropper_Small_898
{
strings:
	$a0 = { 450068471040006a00ff15ee??45006a00ff15ae??45006f70656e004d5a50000200000004000f00ffff0000b80000000000000040001a00000000000000000000000000000000000000000000000000000000000000000000010000ba10000e1fb409cd21b8014ccd2190905468 }

condition:
	$a0
}

        