rule Win_Worm_Mytob_334
{
strings:
	$a0 = { 4d476949db776e3e4a6ad1aedc5ad6d9660bdf40f03bd83753ffffffffaebca9c59ebbde7fcfb247e9ffb5301cf2bdbd8ac2baca3093b353a6a3b42405ffffffff36d0ba9306d7cd2957de54bf67d9232e7a66b3b84a61c4021b685d942b6f2a37df88ffffbe0bb4a18e0cc31bdf055a8def022d2d73f25249564deeff4bff5347202573203a419965707465642e0d0a002100400376 }

condition:
	$a0
}

        