rule Win_Trojan_Qhost_147
{
strings:
	$a0 = { 3037362e303233302e3036372e30333530206f646e6f6b6c6173736e696b692e7275203037362e303233302e3036372e30333530207777772e6d61696c2e7275203037362e303233302e3036372e30333530206d61696c2e7275 }

condition:
	$a0
}

        