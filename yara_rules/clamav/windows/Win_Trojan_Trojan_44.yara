rule Win_Trojan_Trojan_44
{
strings:
	$a0 = { ce28f52d6362fbcd6e9ad2f8ee88f03ddb9e9a5b1717585c3bffd5de632d630f1eaa7fb4aa63544ccde9795b5a6ccfc59eb77ef7fcc6624fd82aa7fab5a0d0e7a727f5ff76993d58bcd682fa3d90d1bc66506543774ddcd6bb27466f8f786e45eb539aa6a35fec38dbb96868d7c9f0b6d6230f2677b7 }

condition:
	$a0
}

        
