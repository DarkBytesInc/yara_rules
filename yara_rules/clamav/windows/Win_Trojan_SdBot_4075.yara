rule Win_Trojan_SdBot_4075
{
strings:
	$a0 = { b1c7aad2e8b3e971648afa5830b8624a23e1b92cb8a2a1ef68717bc609abc04974439a3c0114bc67284c0cd5f9a449b4aebfa20eeafc507187c56cd85d0619061f8419b7ec3d13aebd40840fab6a2c3ca419fee7b7f7 }

condition:
	$a0
}

        
