rule Win_Spyware_W32_16
{
strings:
	$a0 = { 0159c3b007d39ac9179b63f7aa2399a24c4204060bc737b2b76cb0f6f0698003192aeefbfc465e017fee622fb608a15db5c1b2816ebe19a52664f734b27545aa }

condition:
	$a0
}

        
