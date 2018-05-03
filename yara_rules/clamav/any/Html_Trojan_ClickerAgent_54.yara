rule Html_Trojan_ClickerAgent_54
{
strings:
	$a0 = { 5e602088d833b5efa7d4eed6f147a39b075a0d5e0d4cd6dceaf148f4ae5ecb0a43f85ff2b91f9ba04a9ba38d7d76250d57f842a8b3d0f73bf214501564826ad3ee172edfac55a9d7fcc2c2cd55d89ddbac2d8f06a7e9379fd294947b86e0c6d046fc8f7e81108797a0494c57f30b62ecd141bc8b298d6c32fa5fd3 }

condition:
	$a0
}

        
