rule Win_Trojan_Spambot_131
{
strings:
	$a0 = { 76c3c3fb645cb22d038764564578a8843ccb9d8e74e1ffffffff6dbe36bf20f16d9393868b8c9df5d2708f1cbbb02887d5672432902cbf8ac88bffffffff5f9e594bc2bd961d00bb5efa812fd5d6d714f9bcd8910ae2a3d20d692d8ad5427f21e1ff4ad0285f329b0218348454e5 }

condition:
	$a0
}

        
