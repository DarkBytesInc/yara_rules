rule Win_Trojan_Poebot_41
{
strings:
	$a0 = { 610fad23629e3e7f36cb7c5134178e78d52ed97650e15bc745584ec4ed3078c79c6135d2e1adf1a6e2d2e5d67a8c21d67674c8300cf4cb80b4af606ebb4bd0a7432d4376432c07deeacc917800da1de94b8b2ec8541723af5ea98e8f667cf8cbc7980a00fdabffa82787d55843433805fc6b0abf41b300e6 }

condition:
	$a0
}

        