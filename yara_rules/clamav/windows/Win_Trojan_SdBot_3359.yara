rule Win_Trojan_SdBot_3359
{
strings:
	$a0 = { de3ad517e3838abfaad68cc496277282c7caf9849058f3cbadb4eb447e7743255382e6af5c3f6462cf9e118ff0d5f23391e39557958b3560a7a3ea09f7c20e04bd4d99fdcbf8ef8e1325169450a8e762e46ad68cabdf3f557e7ff44c211386735122e7d2022e7d6dd69485980a822a4828457e95186c881af892ec5441a8b3c10f5b12eab7c62de2f41b9f47e402df20e189bf8f01ed }

condition:
	$a0
}

        