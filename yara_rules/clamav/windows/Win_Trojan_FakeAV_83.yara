rule Win_Trojan_FakeAV_83
{
strings:
	$a0 = { 89e8e852000000c35b00000031dd000000004757a3005c0000745400e400f1c810e6b648bb00e2006c00c2 }

condition:
	$a0
}

        
