rule Win_Worm_Stration_435
{
strings:
	$a0 = { 606256f75f5afdd7627b91649b673b11e3f0a6e73cc886d28e98ea3b42004a258dd2eec187d337e0a9b6949ed2a6a5d7e7f1618d9e56ebffe3ca55807734414a359f91cac8b1057af6ef6fd8d714c230 }

condition:
	$a0
}

        
