rule Win_Trojan_Bancos_1307
{
strings:
	$a0 = { 119eeec18657e5af3b59d384eab1da3010da015612d93d67b04c361ed5ccb3e45af2cea5a42d236a2ffd3b524168b65eef485ad1b8337d2fc41fe9ab8e2507c78c460601d68cfa7114822c451871c2749fff }

condition:
	$a0
}

        
