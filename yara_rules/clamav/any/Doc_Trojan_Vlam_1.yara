rule Doc_Trojan_Vlam_1
{
strings:
	$a0 = { 6c696e657328313929203d2022abc4f5f5e9ece6e4f1eceaebabc6eae8e8e4ebe1c7e4f7f6ada7d1eaeae9f6a7acabc6eaebf1f7eae9f6ada7e8e4e6f7eaa7acabc0ebe4e7e9e0e1a5b8a5add7ebe1a5afa5b5ac22 }

condition:
	$a0
}

        
