rule Win_Trojan_Mybot_8323
{
strings:
	$a0 = { 496d6cd173180cd54e44db5f7377b6d0a3473b3f7eb9ab4fa3739190f8f7abaf83f25edf93979e1dde20a1ab56bdff85897331301817cbcfb6bdf782726af1c5b94f3fc643f86c0f644e53bf2f9e9b4bc4483ceb0f696c38625ed7cbb48d7035613e32c6 }

condition:
	$a0
}

        
