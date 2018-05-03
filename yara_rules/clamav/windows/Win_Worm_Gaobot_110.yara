rule Win_Worm_Gaobot_110
{
strings:
	$a0 = { 6c26bdd2cd764b4e470c0b4913f0ff1b5bc9330749524328307825382e3858682931765d2839fb636974643a71baef2d83 }

condition:
	$a0
}

        
