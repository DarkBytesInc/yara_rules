rule Win_Trojan_SdBot_4508
{
strings:
	$a0 = { 6b8feca152ec6b03d791a13c25d7ffdfb5b090304c14ec1fee1c9b919157ded17f82f7c2bb31108c28eac6e16f4023f7128e9dc28b369d3cb8d0e5f3b8cf6745d56a4079bd8865aad770d36af161b64b1ad639e4c3 }

condition:
	$a0
}

        
