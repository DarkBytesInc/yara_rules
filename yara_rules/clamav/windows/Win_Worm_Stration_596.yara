rule Win_Worm_Stration_596
{
strings:
	$a0 = { 57127e71320000004f69756879536b72796e5b6975781c00b9a5acbebdabb8afb6b993878b849e8f89b6a3849e8f9884 }

condition:
	$a0
}

        
