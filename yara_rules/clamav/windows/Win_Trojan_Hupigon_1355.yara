rule Win_Trojan_Hupigon_1355
{
strings:
	$a0 = { 81f2fa1b7423f119d44cfd388f560121c95f65e602ef9594ee53401016e621a1798a075aeda446c0536a348bcc311478f6d5dc7bcd156e8fce11e1efcb84e06f4677ccbba0f2e9cf1c39e8e217e462fc93bcb7e9c0fe902681e83fb88bef9cc42d6c }

condition:
	$a0
}

        
