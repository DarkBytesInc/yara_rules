rule Win_Spyware_Banker_4541
{
strings:
	$a0 = { 0a23b1735c77fe419740b262f301f7a8675424d2c3ed2e8c3a28c919b8bc5c6d622c47c4efbad814a545b2fb21f63f6b7b9fe1180eb3f1aa13dad92ac3af37ab40c9db2a58deba66e7dc70b7b5385911176b15eb5220afc3bafae3a36e2db13426b302c8 }

condition:
	$a0
}

        
