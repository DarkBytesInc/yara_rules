rule Email_Trojan_Trojan_754
{
strings:
	$a0 = { 506c656173652c20636865636b2074686520696e666f726d6174696f6e20616e6420726566657220746f20436f64652052323120746f206765742064657461696c730a202061626f757420796f757220636f6d70616e79207061796d656e7420696e207472616e73616374696f6e20636f6e74616374732073656374696f6e }

condition:
	$a0
}

        