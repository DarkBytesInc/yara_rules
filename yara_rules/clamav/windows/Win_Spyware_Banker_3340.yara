rule Win_Spyware_Banker_3340
{
strings:
	$a0 = { f705ac9049af4228c9e230807c1d64781d50eaeb4ca001b303f482c1ba49760a734b3444aba08267edb38e604be517832c2cfcce42bdb83131a262a4fcad9db97850031d093577f45e2c9a7ab3ac0edbd8ad08fae1 }

condition:
	$a0
}

        
