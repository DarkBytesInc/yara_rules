rule Win_Spyware_Banker_3478
{
strings:
	$a0 = { 04c008e12546f26c16023110c802063843c80427d5b9ea07ab021eab159914020202010c190fc802de10d320d996e166e202e10c05810302020e10c8093fc13eb96bcd0e0249605c78d8ab012a8bd50141dc482d1cda0213aa87394ab7ca3c7357b56655cfa57353405d549c50d55daec8df270b5050a5647e0247084b102b214d903f660d480243362038cc25250246 }

condition:
	$a0
}

        