rule Win_Trojan_Spambot_122
{
strings:
	$a0 = { b929b560075e41ff72ea41b80204b6ff7ff1ffb2cb49f7c5fc70c3ba6d346c3b2d4d16293cd631ffa55392a621ffffffffef70412577dd04c8b59ef0a6aef66f969e5cd6cdb245938e4d62274c728c742cffffffff625b3c66a0db2d9b7635eaf2166843c7a236d72a55c7dbdf8e }

condition:
	$a0
}

        
