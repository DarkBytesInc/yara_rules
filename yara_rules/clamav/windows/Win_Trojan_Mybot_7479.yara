rule Win_Trojan_Mybot_7479
{
strings:
	$a0 = { 7374c6327c227c86d77649b7407e974fb6072863ead63121bd69c7dad98d630534beb8f64b75ffa0830adb389598ade3b932e8d01306085a9da8fdc15c7440c3116e0c45be2be3fbe7cc0d6b4980e4ec08adac7eb2cb32a4abc4e2eec476ac1513b767c0f77d8b5aa1334a4fa69ecefa2a8933b68ca38ac1763cd22e4c94886e7daa }

condition:
	$a0
}

        