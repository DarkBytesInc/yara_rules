rule Win_Trojan_Bancos_1972
{
strings:
	$a0 = { 52ebd9d8814e9ec0611d9fbc3be0c8fc905b641295d5d4174551ef9cb546a491e0654782330ffb627e5319cec02b96ed86ce10be06f7d7a399989066390144c2df275e64a87adf1188efcbe9be529846af42a9568e93d0a18abf5bfa10343b02035913ca53c91bda6986cd845907 }

condition:
	$a0
}

        