rule Html_Trojan_ClickerVB_45
{
strings:
	$a0 = { 8b45e88d4ddc51508b10ff522c3bc7dbe27d168b55e88b1d301040006a2c68102b40005250ffd3eb068b1d301040008b45dc48746748756a393d785440007510687854400068d4224000ff15b81040008b35785440008d4de051568b06ff50143bc7dbe27d0b6a1468c42240005650ffd38b45e08b4de451508b108bf0ff52643bc7dbe27d0b6a6468e42240005650ffd38d4de0ff15 }

condition:
	$a0
}

        