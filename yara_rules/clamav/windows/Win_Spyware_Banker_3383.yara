rule Win_Spyware_Banker_3383
{
strings:
	$a0 = { 5c11ef2cce57aee06392e0dc2203e8ca9eec08da4cc8d0756056d9f520ea791fbde47c6320d4669cb0ef7e18d2e11050728b17626599764487599545be6c20a812c20857cc1851bfe2846769eecdb6fed461aaa94a }

condition:
	$a0
}

        
