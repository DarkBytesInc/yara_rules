rule Win_Worm_Stration_751
{
strings:
	$a0 = { 01022a21592111ff65306403f32013d22a2354e30197996f5101141b142c11362101002fac85c28e02013f11f6c2a08d0077f24d0fc0808117f304272e0c183060353c434a6020020751d3a6060c1830adb4bbc2c0800103c9d0d7181c3060dee5ec9f28e9eb4ef5ca03ce0f4879ddaa5235e3387002f64572d92eb4b88cb9802301130b843853b6c3100801201c6052bfaa55534552 }

condition:
	$a0
}

        