rule Win_Spyware_Banker_2781
{
strings:
	$a0 = { c97bd6fa0ddd1d5769e8b818a52f078b6017e4d3acd1961e14dcfdc201f4031f34a433a0b0b76b7e891eae6bbb76087752da4cbd2b8aebd66393946b8f085e0e0a9303aa5f1ebadf86e647153f8b0039c348e669ccf4eb7f17fdc4ebe5bcf0ed9927040b }

condition:
	$a0
}

        
