rule Win_Spyware_416_2
{
strings:
	$a0 = { 0252a75debb00f91c58aad03990de2af69ff6e63d479655128f52fba76f2fe4955139e1a57f7a756f2b408921baca34aecb2b8731a7af2e29dc272b63c052678fde5cf506e328fe2a175860d2195 }

condition:
	$a0
}

        
