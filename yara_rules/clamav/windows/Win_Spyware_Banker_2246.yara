rule Win_Spyware_Banker_2246
{
strings:
	$a0 = { 2f749528712dae12ce6e750b5bc539746b3fff9032ad8dbfe78c014c3741097bc0ecde368fdf4897347735653b7c3db941a8a2b39aee4bec034a0a096b24b6baee5e587e373ad9266183e2fb3cbfe6b64df10e7ce19a3ca5a0654d9eb6a3ba39a8dc3452 }

condition:
	$a0
}

        
