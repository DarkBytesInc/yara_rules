rule Win_Trojan_Mybot_8500
{
strings:
	$a0 = { 8c3420137e5bfc1c3ede4123cf3965783ae75c45168563aee0074ded4f8ee7a9aba1b46dceae8a13f26f218f1fecf0d8a8735a22bc9274b57d95ecab9b03ef794c37b25f397b451bc973b3d036264dddc3d16485ff }

condition:
	$a0
}

        
