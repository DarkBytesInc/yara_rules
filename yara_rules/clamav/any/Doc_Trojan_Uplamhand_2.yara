rule Doc_Trojan_Uplamhand_2
{
strings:
	$a0 = { 576f726442617369632e436861724c656674203136 }
	$a1 = { 576f726442617369632e4c696e6555702035 }
	$a2 = { 734d6524203d20576f726442617369632e5b46696c654e616d65245d2829 }
	$a3 = { 4d6163726f24203d20734d6524202b20223a4175746f4f70656e22 }
	$a4 = { 576f726442617369632e4d6163726f436f70792022476c6f62616c3a4564697453697a65222c204d6163726f242c2031 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}

        