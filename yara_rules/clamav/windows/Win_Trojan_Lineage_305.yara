rule Win_Trojan_Lineage_305
{
strings:
	$a0 = { 125010570fab20d7d71719b013a43376575e2ea993dd424af7eea50b73b7561cb8637b72e4bc1e6ef36f1c5711432d8a1ee1eae5d336ccc737dd8ae5fb9da13f77f27a7a9e068122dc7c5f81309e3b3e1e03eb05fdc6f0965e1cc93b }

condition:
	$a0
}

        
