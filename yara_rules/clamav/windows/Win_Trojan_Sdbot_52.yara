rule Win_Trojan_Sdbot_52
{
strings:
	$a0 = { df00eac8accbe41530e0b6c0e2417af65303fb152db1a577d09369f3da329cc0c95b3f5a03c2ec52a347e4f812a7caadcafd19afaca5dd08a6f7ee9dd22ac0a3fca0ac0b407c02673c859a2a676d1dbda5ead3a478ae708cf6d37bd5f88093c1e492d878b085d3ac9c28b57b3d929db830f95a5415557830 }

condition:
	$a0
}

        
