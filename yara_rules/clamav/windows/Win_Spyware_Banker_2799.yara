rule Win_Spyware_Banker_2799
{
strings:
	$a0 = { 07cc31d5101fd03d11e36dbda04641459636d023f35d0d3e2f80c245ebf6dc1b2b63dc845ec5c8c3c13c9c7ebf4c8181085c2e17cf57cf30fd549051b87377fa753e8c10a784470d6ed111f044e1c8b7ea215ea351cafefe3c7c45a5499fc5374494d596 }

condition:
	$a0
}

        