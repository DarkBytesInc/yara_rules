rule Win_Spyware_Banker_1154
{
strings:
	$a0 = { 9f5cd32f423aa6991617553ffaff3f12d6220bf5b3dad63b8daf79b9ebf19e8bbe151be6d435ff3f13fe69c8e71ab38cd28b50f6e935533329f641f61c64d4fcff17ff901d150256c89b3c3174982890afc94572959a2c2c9653 }

condition:
	$a0
}

        