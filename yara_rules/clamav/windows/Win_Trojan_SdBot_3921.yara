rule Win_Trojan_SdBot_3921
{
strings:
	$a0 = { 5164dff778acbaa867350e4a41f48daaf67c860bb969ba6319a1526ceed6a7922fb2ee36db1790d28f1e0e2ecbb2bdb3fbee87585f149a29a5ebe2730e960d48f4d2acb0d57154196771354ed416a5924f7aff89f7e19377a8a02e8c }

condition:
	$a0
}

        
