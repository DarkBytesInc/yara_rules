rule Win_Trojan_Hupigon_1178
{
strings:
	$a0 = { 13ef1bd4107dcdf9312cfde16cf7b244d2b715a4a244efa91b94abdf367d905605d7ddf9891a223c28133477bf930f399dc2b9ce015a3730e95dee6d4598104bdd3acb6f47ee7a52153041239edbfd56ffa22d4b931fe0ce36d4d21f11cd70ce5d1df8720308ca6cba2043278decfddffd9d815e2ddeaa9fab09e2231908548c5771949ca3f9debcb90c49f9 }

condition:
	$a0
}

        