rule Win_Trojan_StealthSpy_3
{
strings:
	$a0 = { 54484520454e44204f462046494c453e7d003230330d0a4c6f67696e20696e636f72726563742e2e2e0d0a000000496620796f7520617265206e657720757365202768656c702720636f6d6d616e642e0d0a000000000d0a57656c636f6d6520746f20537465616c7468537079207365727665720d0a000000003230340d0a4c6f6767656420696e2e2e2e0d0a000d0a0000506c6561736520656e7465722070617373776f7264 }

condition:
	$a0
}

        