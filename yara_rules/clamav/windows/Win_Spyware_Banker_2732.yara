rule Win_Spyware_Banker_2732
{
strings:
	$a0 = { 16ba8ed71208bfaa9123e4d5cea52ea95ddbb32017a8f94f6b3fa2b1051018fb1573f79d34dcae5516d4d6653acd3241c5a758ae32ae8e7f81eb215ec0ce79712701ca87357d93d0155272d623e7 }

condition:
	$a0
}

        
