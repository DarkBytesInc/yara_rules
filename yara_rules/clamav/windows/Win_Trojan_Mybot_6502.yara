rule Win_Trojan_Mybot_6502
{
strings:
	$a0 = { 301e11431b7b1170feaf8b0609b894669a6496b51bfe40591073d069344181e375b171ee7f2c86d7b00476b3e513909617d5aa7aae2b1df281ee3e53ef20c86372737a4793fca907993a86f9db0293dae463899c4d1a936eff3750afe1dde221536e75737ec2ca5b0021bca200db9fc3c36677c8740f0809e92a9ed40ae168744ff7776d32dccf0da2beb4887b90b360c75fc82e19b7 }

condition:
	$a0
}

        