rule Win_Trojan_SdBot_2307
{
strings:
	$a0 = { ff57d7f4a9b3a8b0ed949999330ab6fd578ee66e35df7e345586f9f30b0bff391ee87e337ec3a59d7ee57ce4350d2c730a7ca4260abafdacce31f742459f802879c37cc52adc7fe33335f4fa71ac53f1701180a67b3c01b5fde3fd4dceb02d677ca1a1169a37a6d276705996a5c197b83be5114aa48a45f189aa1978f9457ef4eba57fe5750fd81b1b5e }

condition:
	$a0
}

        