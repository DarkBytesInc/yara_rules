rule Win_Worm_Lovgate_13
{
strings:
	$a0 = { 3f8ae5221e4c77c4e97e6754f75f8a7101679efce90d5acefc7b9b81ed0d61a46b77aedb44f1c0a98dba1eca1e1f9616ba7d1baa2cfb85534fe156bdcff542a2e8feeee297bfae785e107a89db417d0e623a459a90f061b306d1cc98c8cf7253fbbaaec3c1ddcae291551386a8cd1116 }

condition:
	$a0
}

        
