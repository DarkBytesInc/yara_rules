rule Html_Phishing_Pay_137
{
strings:
	$a0 = { 796f752068617665206164646564 }
	$a1 = { 696620796f7520646964206e6f7420617574686f72697a652074686973206368616e6765206f7220696620796f75206e65656420617373697374616e6365[0-4]7769746820796f7572206163636f756e742c20706c6561736520636f6e746163742070617970616c20637573746f6d657220736572766963652061743a }

condition:
	$a0 and $a1
}

        