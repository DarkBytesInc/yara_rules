rule Win_Trojan_SdBot_4159
{
strings:
	$a0 = { 654e421c9b6a506864761d510f257fbcb6835c92662e54a7228c918e4d229d8adb6ef031a6a21c1e0550c5bf0e081093d598ce01c80149b6114ef80f5f3df5a0e1b9b114575e0b33a1ac57f96cb259fc7c7ec0faef4b6a7d0d7f1665d1aa89262eeefdf3041fbebe4b510a434058d7ed5629baf2a7839d47bad43d0ea0366433 }

condition:
	$a0
}

        