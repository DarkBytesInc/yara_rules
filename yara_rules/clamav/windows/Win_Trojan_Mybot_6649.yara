rule Win_Trojan_Mybot_6649
{
strings:
	$a0 = { a71c3d178f27bd570f16c36cfef1789f6a4a84434888976873b9eb855fe7916ed9304ff279f8b53f9e05a1851ec8a552547528e8bf8e87ff26455ba077c3a4ff81e2948a576ad25edf2a430d92e4241e0aebcc2b745f0f6226b1fc24695b58cf63592b4d5215880c14c39da60b3e17e8037a771f5eaaa84e686a551743e42929c7badbbe19cb9e2b3fc89069004942f2d3ac625f23a8 }

condition:
	$a0
}

        