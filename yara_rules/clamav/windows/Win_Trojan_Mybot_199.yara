rule Win_Trojan_Mybot_199
{
strings:
	$a0 = { d2d82bf390ea22989b460bdfb22e9a3c85dc19af47342b60d0731b9a381f6e51de19bd081f32c613ba29743483a3d3616674a1581c5bae81f3c8715ee55d18ee576f60410d21590584fd6f58245bea188330842b05eefd33626c346e1ca1c20c2f707f2ec1881dec976c476b09039710a5279d554fa5889b6fac44b60ee021e3bb4aa8b5bad4a6962b42 }

condition:
	$a0
}

        