rule Win_Dropper_Delf_985
{
strings:
	$a0 = { 6a0068800000006a036a006a0168000000808d55c033c0e88eebffff8b45c0e836f1ffff50e8ccf4ffffa32c414000a18442400085c07e548945ecbe88424000bfd0424000c745e030414000 }

condition:
	$a0
}

        