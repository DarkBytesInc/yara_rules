rule Win_Trojan_Gen_143
{
strings:
	$a0 = { 30cd213c027301c38cdf8b3602002e893ee4012bf781fe00107203be0010b8a04305fe07730ee8900533c050e89108 }

condition:
	$a0
}

        
