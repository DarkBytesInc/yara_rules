rule Win_Trojan_SdBot_3894
{
strings:
	$a0 = { 2cd8e3594acf9e9bbab319ad082a7292257f47f5e23051f035ff24f3449d6bed4d6c0ba1348a7e0e4f48ef518f74ef00ffdd9082bb7486acf55971ddf0adc7b410c53fafbef707b6fc81818cf594b6ea579f0f172c5613aefbdff616 }

condition:
	$a0
}

        
