rule Win_Trojan_Hupigon_1492
{
strings:
	$a0 = { c7e8d58bab7e3dbd62f1c6ce6aaf7a4c90aac6a5b017e567d14d80c46fcb6a7455c45d087ca1d221724e11befc7491b618756bb2cc63397349548715772a8ea2ed300c33204e152546bc9d14bf7fde4d230e85670ec7f43b3e10d0ee2a22e010c68dbf130c78fa95dea84a8bc93f81beb6d7c2078d005882cdc227c235981e2ea17f79ef47a5c18885e63314 }

condition:
	$a0
}

        