rule Win_Trojan_SdBot_1890
{
strings:
	$a0 = { 5540236e6b2556bdfd87b7aa802be60c940b3ff1ae63a35573213e041d7bca6f09c137eca86398152be95b86681cfa59133b77e706180250bfc36d4b30b06fddc6b94068c46cb878d8eae701b2b5 }

condition:
	$a0
}

        
