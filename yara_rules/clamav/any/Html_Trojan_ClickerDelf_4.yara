rule Html_Trojan_ClickerDelf_4
{
strings:
	$a0 = { 6163652f746564657972652e68746d6c00000000558bec33c055689b38400064ff3064892033c05a595964891068a2384000c3e9 }

condition:
	$a0
}

        