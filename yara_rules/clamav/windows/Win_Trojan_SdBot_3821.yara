rule Win_Trojan_SdBot_3821
{
strings:
	$a0 = { 798dfc9ddf308506897c0f220fb482bdacd04e738504fae7d75050d16f1498d4bcff82c01518ff363715b8cc440003eaf89775eb0000a95097eb7f9fc2ffb08a3dc4af4f5f110deac8b4c3ff7d432c191030130da8d9feff0085bc935af0af8ccea7 }

condition:
	$a0
}

        
