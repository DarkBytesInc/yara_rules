rule Win_Trojan_BookKiller_1
{
strings:
	$a0 = { cd21b405b200b600b500b101b008cd1349cd2020c9cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdbb0d0a00ba20204e657720426f6f744b696c6c6572ba0d0a00ba20202056657273696f6e20312e352020ba0d0a00c8cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdbc0d0a24 }

condition:
	$a0
}

        
