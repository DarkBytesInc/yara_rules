rule Doc_Trojan_Kompu_4
{
strings:
	$a0 = { 274d616b726f766969727573204b6f6d7075 }
	$a1 = { 7369632e4d6163726f436f707920576f726442617369632e5b4d6163726f46696c654e616d65245d28224175746f4f70656e2229202b20223a4175746f4f70656e222c2022476c6f62616c3a4175746f4f70656e22 }

condition:
	$a0 and $a1
}

        