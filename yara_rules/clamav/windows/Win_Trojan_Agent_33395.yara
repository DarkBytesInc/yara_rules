rule Win_Trojan_Agent_33395
{
strings:
	$a0 = { e4abda3608c5eeb53df130186fb140f5300ad5743f75abbedd22a4232df643449cb6b727812c227ad808bbdeb1191237e9a76cf56fd31bb1c23d33e2fd14c11c84295b2ef8fd9da0f970bf7a0bc061915dcc3349d9403c231c386ce3ebebc23a47f94008c7e0d40dd1d38696abeb13cfc8d9d3068c3e3abfeb6d65aa66e5f1d507d77685b483c64a8d4d836fa52d6588c8d0395a3521 }

condition:
	$a0
}

        