rule Win_Dropper_Agent_34644
{
strings:
	$a0 = { 81f879a6990033c78d3d84742402c1c8bffff14089c085c7f7d159c1d9e768dfcc27004a5a8d2de60985028bedbb3fae9301d681c77c8b1bfefff2f85d89dad6fc81ef0426ffffb93d61f1018d0d9024d3013cf6f7d33acf84c58bf7bb56deca01f7dabb }

condition:
	$a0
}

        
