rule Win_Worm_Mytob_358
{
strings:
	$a0 = { 9e3c684e3fec8df16c3e20a03cdc0b42523e3c262ec4163e52223e4498609f688620f604d93c2f1644f58bbd222c08596f6d44eba05ef720a4ad73a0b42d6d31758979347058346dadebc920f120ed1577b62026bc382c5120851fedd86193b5694a007b4924100dadc120d62f5220a019dacd953b697a46d637b601ade0b7ac0b2c692736e75c61d96560e71963059b9958776965 }

condition:
	$a0
}

        