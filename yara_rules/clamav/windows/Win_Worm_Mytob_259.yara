rule Win_Worm_Mytob_259
{
strings:
	$a0 = { 394ac3211a45e45c239ecd21f55be5fba083cc14876816fba1e10d90d4d9a240304f8542b39075e45defe9a8e1e59bc156b2a4f63339417be4a6de24b93d4e5cc325feb966f0de53674c33f8622689588c5259d8b5dd72724f11ba8a21006231ec6813c4fbd976bd477d8466899c95c3caf6e28b1eaced9f3123a48f2a62f49a3b04117ed522045697062d5a2649ea1c857be274c3d8 }

condition:
	$a0
}

        