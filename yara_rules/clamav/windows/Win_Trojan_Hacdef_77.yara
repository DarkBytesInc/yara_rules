rule Win_Trojan_Hacdef_77
{
strings:
	$a0 = { 09ea14800a66b795bd8bbec8c0e2e5883d5bbcae046e32aaff538532c1d7d26a2a77daa0f631b15d5a074eb2bfd401bd77db241ac2e96548fcced868e3b0f08bca0bbd3215ad3f22c4e4ce0a013d6f769afe7a466f80e27fc29d9260f54c8de57ece0d130383a14ab78d92ea6c7d2a57de4301c5e3ec8d852dc399 }

condition:
	$a0
}

        
