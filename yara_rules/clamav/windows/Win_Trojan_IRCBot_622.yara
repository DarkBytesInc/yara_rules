rule Win_Trojan_IRCBot_622
{
strings:
	$a0 = { a33dea104bd42393de2cb0bef85f5b09bf5f419f9e6f089da111f0e41b54b9ffe07122a63742b525ac0e2b481dc5ef1c09fddac36a4544cf7396e254983ec55204cc48a06dcb356f4dd0f8363bceaffd82e911d8880307f07687 }

condition:
	$a0
}

        
