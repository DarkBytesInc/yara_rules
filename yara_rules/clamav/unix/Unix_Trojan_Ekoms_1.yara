rule Unix_Trojan_Ekoms_1
{
strings:
	$a0 = { 6d6f7a696c6c612f6669726566 }
	$a1 = { 456e7472795d0a547970653d4170706c69636174696f6e0a4e616d }
	$a2 = { 65726d696e616c3d66 }
	$a3 = { 687474703a2f2f }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
