rule Win_Spyware_Banker_356
{
strings:
	$a0 = { 2dc2f7f7be2291388fcc4fc6f3dd559ce28de03f8b685e937a60390fd5752dff4708964c4b454547516b745321e513baffd3945303e61a914f4f269924bf8fef339077934c1e98bb276bb3575707cc13a3fc62ec75a50f5339d486c25ef4a8aaebd08465e70adcf2dffbba560fc6e3c72327789c4e1e23c730e246f1be828ed2d1a6a841a803610f70d155b8c574aaae91d468f5efb8 }

condition:
	$a0
}

        