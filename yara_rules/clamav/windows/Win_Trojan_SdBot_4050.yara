rule Win_Trojan_SdBot_4050
{
strings:
	$a0 = { afb74b3abfc1e8d61fff36609a68e9d8c88f49ea66e1aebb9b30a48c8eb3ab3d0dec341ec73f6221b7903d035e95fecaf13e9dd7b3c54d30930caedfb8436d27e0d1f40b58626eb2c82e0dff641592dd0d20458b4f30 }

condition:
	$a0
}

        
