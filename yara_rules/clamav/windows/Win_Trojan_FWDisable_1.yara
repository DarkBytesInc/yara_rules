rule Win_Trojan_FWDisable_1
{
strings:
	$a0 = { 28290d0a0952656757726974652827484b45595f4c4f43414c5f4d414348494e455c53595354454d5c43757272656e74436f6e74726f6c5365745c53657276696365735c5368617265644163636573735c506172616d65746572735c4669726577616c6c506f6c6963795c5374616e6461726450726f66696c65272c202244697361626c654e6f74696669636174696f6e73222c20225245475f44574f5244222c2031 }

condition:
	$a0
}

        