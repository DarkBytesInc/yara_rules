rule Win_Trojan_MemoryLapse_4
{
strings:
	$a0 = { e800005f81ef030187ef1e060e0e071f8dbe81018db68901b90400f3a5b41a8d96de02e837001e06b82135e82f00061f87dab80325e82500071fc686c10200b4 }

condition:
	$a0
}

        
