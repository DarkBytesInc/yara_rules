rule Win_Spyware_Banker_1532
{
strings:
	$a0 = { e981271001fcabeaeaefa5898886838fe1df01c00a03d694b0bcbcabc998b9bfac4580115683e9c3c4fcd6dcce11c5e0c34922f11a03e084acabe2c4ddcdc0c3d7a00b4300c62060e3105ac1e4ac58e290d1ebe926f831008428110f18788af16624658064280c0e0800cb85b56638821726cac15f52002601e0095929 }

condition:
	$a0
}

        