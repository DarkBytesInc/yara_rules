rule Win_Trojan_Small_3364
{
strings:
	$a0 = { 3d50b2174edcf9689f8619797c3562d4c3caba681392ac9c5875d094a77ca7592183fd93f6aba218e236a2dfee7691aa63796b372f7028fa228b6cb22ccbf3582f511eecbd90c2297a52c5718dc4d85c4fbeed1f150a85f4aa15bfd7a4bc13cf }

condition:
	$a0
}

        
