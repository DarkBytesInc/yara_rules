rule Win_Trojan_Mybot_5456
{
strings:
	$a0 = { f64fd482e912363b895020db5b2d07c8812a0a101a74d4af1f9e554f57ec37f2621f478f1a750beab33d42bcbf01a21b24be9cb73f7ebb36e9b999db9cb7f5f793fed9fc05b62de46123574f85f7623aa6259edc3b50e36c4aa0af74d6aa8eb4edf21ff3e39aca89b3 }

condition:
	$a0
}

        
