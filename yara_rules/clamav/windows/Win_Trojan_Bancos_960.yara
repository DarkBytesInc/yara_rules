rule Win_Trojan_Bancos_960
{
strings:
	$a0 = { c1acf5b75d147938e270c03f55e6c1aa2b64fe734c590e6f32103d296c23f9256fab87da8c99237fca5687e79cc9375d2805654432b63563e7858974afc1d0cf15f1c072279d09f9438ea309c9bd5469fa21004de3 }

condition:
	$a0
}

        