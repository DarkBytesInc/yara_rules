rule Win_Trojan_Dialer_926
{
strings:
	$a0 = { e0886a6cb0896fe6870ab50d754d6c187af74c7c776193811501f6692168808d7c1070487cb963b237837938b30ca7af8a4f0f1618ad942cfb589e56e26f0be1e97bf1a4c12cd70e182b9ce29781aab40c452678f0f46f5cb95a12945001cf69f38dfad645325979f62e4cc1c1deb4ef058a04434dae596c9ac2c9dc164c5c0c2cdc65fb36e8c09542ba7e15 }

condition:
	$a0
}

        