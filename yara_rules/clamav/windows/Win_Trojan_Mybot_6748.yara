rule Win_Trojan_Mybot_6748
{
strings:
	$a0 = { 4485e66fa3a28783ef3ed8ede73cbae5d0dac799b553fb0a1c855c388b6e7d14e0104762d45ec8fd882dc37eac3a37fb3ac3a42d7f2a08a4a411c4d77564b1e07dbeb5fb2d34a5d58fa31502f9f5f6f246112a8ea063464eb4140ce0dae6271fb5f195704b06c4d93bbb215b25518d2ea684cb32bce6b8f71a37eea133f23d91cb8c6a98b2742275e6a5b6bdbb21606b7f1d8d486b8b }

condition:
	$a0
}

        