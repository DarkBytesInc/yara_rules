rule Win_Trojan_SdBot_2130
{
strings:
	$a0 = { 5b72deeb835e4cab4be2e0054f48770cd07c31f73beb4617913eed9f01a0d5cc9173d3a8f041bcb1cf3fca9bb875616f19143f7c52d730a9e51336839c630bb9c2f5446abc76268d93ee61b1b1b319aee9567383498d2ee3d98d }

condition:
	$a0
}

        
