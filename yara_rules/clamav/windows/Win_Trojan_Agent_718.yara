rule Win_Trojan_Agent_718
{
strings:
	$a0 = { d2aa153a7fdc524918110500a2d527871be04e7c4f8b7814e081ba126153e11ccfdb5b4a9d255eeb7233736379ac4b2847d068ebbd28ab1e6833560f7bc2b0d8e2e14d8e567458fe1e9d5e1b7f1ca11de59d4df31ef25d5fc529ab506253583367e8250ec8e89651f6cd5a5f0ee0e6c0faed6a7c4c79f40c77a3180b47d84c3020ac5b1f81bac7a46399fd0f62762b604b8a681fe460 }

condition:
	$a0
}

        