rule Win_Trojan_SdBot_1776
{
strings:
	$a0 = { d0fceb033ef3b6d7595340718e62e3eebe338fcba1c14885ca3b0a06ec07ccf98df2fc20c99380366f8e5c5568afdd70d0e8f0a9fdb9e053f3d92ac1248e5a4fb5bb1c33bf42e511f9ce27ce8648aa2c38897b8282e68d8f5007623e0a6734f4de67 }

condition:
	$a0
}

        
