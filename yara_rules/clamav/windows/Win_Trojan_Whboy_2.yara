rule Win_Trojan_Whboy_2
{
strings:
	$a0 = { 76f54e4fa38c492d51a816309a9984dac4a9133b224854447669f7ba642f665f677f934b324b42d1c5ccff64adc4f6b44c35a82a63a01dedbffd4a0aa02656a787c65851ca243789c1d971e43309ec68b8ba6ea496409df1d3a6944ec9d6cbdeca688958d21eba5dfd56e22541efb2cee0251ac32c7ee23a5e021c45116a36cb25f8254ce77bb352d21783ed96d40d25d325d0 }

condition:
	$a0
}

        