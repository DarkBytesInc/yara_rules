rule Win_Spyware_Banker_2629
{
strings:
	$a0 = { 9affd953b1fe8c0fa6ecaff0764fe845913bef25e6740025fa3edbda108cd4007170527a616270224859abf908b53ac75fbc730682b08fe9281bba4b6919c3df4b4234cd30dd6f3d347311a3f80d71deb4e2b8bdc1d8eef9272a7ddea8f7cbd32225 }

condition:
	$a0
}

        
