rule Win_Spyware_133_3
{
strings:
	$a0 = { cb4ab1552b747c3f24a05a7b014d8fd3fc991abf16b18a14a3bff68135140abebd405a7be6f9ea4fdd4c5136019c34fcf751d9e679ea0a36bae699a641a0e66d57d73c68a83753c4eb03a66f85adfe6644f238705c010f10aac6093aba0a }

condition:
	$a0
}

        
