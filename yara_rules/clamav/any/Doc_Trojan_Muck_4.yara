rule Doc_Trojan_Muck_4
{
strings:
	$a0 = { 617369632e4d6163726f436f707920576f726442617369632e5b46696c654e616d65245d2829202b20223a46696c65536176654173222c2022476c6f62616c3a46696c65536176654173222c20457865637574654f }
	$a1 = { 617369632e4d6163726f436f70792022476c6f62616c3a4175746f4f70656e222c20576f726442617369632e5b46696c654e616d65245d2829202b20223a4175746f4f70656e222c20457865637574654f }

condition:
	$a0 and $a1
}

        