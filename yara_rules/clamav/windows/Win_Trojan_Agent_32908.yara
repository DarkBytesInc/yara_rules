rule Win_Trojan_Agent_32908
{
strings:
	$a0 = { 6931a5e55c93ddbf8c603b7a340a4f288f6660b948cf38ff4b13f6ce3254c6f30313982abcc5fb64c500d7db16ee0ea5c353f0faa011953cd20ee48eb492a420ba6518f0aacad481c92d652d7a7f116d75b969a4c8 }

condition:
	$a0
}

        
