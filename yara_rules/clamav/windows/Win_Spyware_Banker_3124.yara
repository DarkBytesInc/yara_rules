rule Win_Spyware_Banker_3124
{
strings:
	$a0 = { 918de280f1d2cf0d3b3d0c5093bb97f1e626ab2a11002736389c193540a82786c68863701861a88be91473e51510a5d8c5b047fa80dccd81a90b4101552cd7ab735b40a473fcc1982a198a89c4539030c6c14240f35ecf0e15e0f3a9aafbbf11f295b71dff785332e6ee272204aadd0241579ac9ef726d7c37a731a8b236f6c8c4bd03a89d35b2f402eb652b }

condition:
	$a0
}

        