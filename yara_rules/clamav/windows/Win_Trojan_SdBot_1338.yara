rule Win_Trojan_SdBot_1338
{
strings:
	$a0 = { 3bc17b040f64650d6344cf17bcbbf2ff6578706c6f6974667470640ab6756bfdfd361b290e06656e537970740e00726177b7c1c1c107de69cb70c4170030b0f667f61b6e7469701e630a4eb877ff6e46ea49767363616e0f0b00 }

condition:
	$a0
}

        