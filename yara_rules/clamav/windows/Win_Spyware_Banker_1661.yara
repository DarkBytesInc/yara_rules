rule Win_Spyware_Banker_1661
{
strings:
	$a0 = { 1d54e84f0f1e1bc880b55aaad0b02392cffdb4c0d40926deb31db76e956db1f636657d74d0eb542e8d9850f866d11f9d6889ee32cc2b1fec8107ec1748bc6767a3ebe3bd9b747abb1776c809c206ed4c1b01522c725f7a0020df5dd0a7adb6fe1d0cc6a518627552fbacfdbdf8f8074eeeecedc196ccf7e459aff92ad47ffb54 }

condition:
	$a0
}

        
