rule Win_Trojan_Prorat_100
{
strings:
	$a0 = { d756e3f3c255532e69603de5a865a126202a32755b915f7524bd9cc50011dc7964b4bc24266422ee7582bbcd39c0c50d0ec3e37cf06963c4e72b49009596698a930fa6c8e1d9a25bb655ee53a5cd8c8a55f5df3501e1608216cc56e33e1bacdfa5dfa50178f5d828ef5c983622403ebb913b403dc11c }

condition:
	$a0
}

        