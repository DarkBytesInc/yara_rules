rule Win_Trojan_Mybot_5209
{
strings:
	$a0 = { 2b4034de630dfaafe8f04f1bd5ea3468304fb67f7afe2bbb8d26df0b301987584fe556db9628a915d9e07b734cd2acf11f228cf9c4bc053d50839f48fd5ba320a9e5c845152bb30c541bf45dec246e54227bdaeb3da5a4bc3d20e1cf808796f6a3a887a7ad988f97ddac9184b6366316fbd74611b4ec3ff3960cfba9df43c3614b2a15168474cdfe55e0f504642ab5f95d582f94 }

condition:
	$a0
}

        