rule Win_Trojan_V_47
{
strings:
	$a0 = { cd213dcdab743eb82435e8720189876a018c876c01b82135e86401898780018c878201fcb9ac012e8b36010181 }

condition:
	$a0
}

        
