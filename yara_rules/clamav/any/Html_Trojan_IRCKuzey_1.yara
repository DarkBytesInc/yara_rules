rule Html_Trojan_IRCKuzey_1
{
strings:
	$a0 = { fc077a513c3f792fd054ad2bc2413d5834374b0eb75d8499e23cb809d83e06788b9a8cda71d428c4881ddcadece93940ad2008e8ef22e4b611efc80f07f05a9b85445cfc6c0eef6dc921abd4435f38e6 }

condition:
	$a0
}

        
