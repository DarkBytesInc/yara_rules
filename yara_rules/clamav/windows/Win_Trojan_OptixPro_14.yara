rule Win_Trojan_OptixPro_14
{
strings:
	$a0 = { b24b65328d6c3682417ef70f0bdaae946b380bff72e4d201066d1eb5f8714877f62c15cc2d5a5a6b15b42575fe15182343833a66470baaf3ae8d93a1cf6bf5ebf6bf8fcdf9205de8cb51ad2c994cb6d3b73f16d75562550bfa1f87a3fc65b50f8bca0c158a26adeb1e0d33dad15f07e1089aae2a8f48f96fa9ab2d }

condition:
	$a0
}

        
