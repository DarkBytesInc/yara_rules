rule Win_Trojan_Method_1
{
strings:
	$a0 = { 6e65574254203d204974656d4578747261637428772c20416c6c5742542c2040746162290d0a0d0a4966204d79436f646520213d204f6e655742540d0a0d0a7669727573203d2046696c654f70656e284d79436f64652c20225245414422290d0a686f7374203d2046696c654f7065 }

condition:
	$a0
}

        