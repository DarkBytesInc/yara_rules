rule Win_Trojan_LDPinch_6
{
strings:
	$a0 = { 6d696b653532406d61696c2e72750d0a0035464342374541390d0a5243505420544f3a2072656e652e6861757377616c643031407765622e64650d0a005375626a6563743a203434353720694e47282573290d0a0d0a0026623d31373434373836202825732926633d00687474 }

condition:
	$a0
}

        