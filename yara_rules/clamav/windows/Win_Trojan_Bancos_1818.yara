rule Win_Trojan_Bancos_1818
{
strings:
	$a0 = { 8a3d04582cd6a9c56cddeb5c872858ccd58697aec24799e8358b6ae66650023b3ac192572cee0ec026151e1169393a51f9dec6e81ac6923a2666e179acd600d7d768a60681ef }

condition:
	$a0
}

        
