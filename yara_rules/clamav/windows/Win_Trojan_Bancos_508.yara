rule Win_Trojan_Bancos_508
{
strings:
	$a0 = { 827cb81180428e32a3f0e025a0ca6f1659d9be44fe03ecd2ec549ab39bacedff0f8e0825253d4865aa36b7e501ee5ea891bc58ad8945364bbc28a5a14e4eaec0f9075e1de612e0b5bb3b950361cbc20d996c2acb6fef2fbbab3e09406392073a6730d828c2a54eba4c3131f775fe3339ac82ff0019ba87ffb6e3e77eb6e01aec38bf11e93b7cc99032ecdb1a3b9d42822f6bdb901f45 }

condition:
	$a0
}

        