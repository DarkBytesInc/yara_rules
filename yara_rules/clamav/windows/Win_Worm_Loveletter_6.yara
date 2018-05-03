rule Win_Worm_Loveletter_6
{
strings:
	$a0 = { a8192669a41e600d02b76681f7fbb68584be590e42bb54460480eb4e10ff25a80000fcee582d776f726d2076312e3120426163 }

condition:
	$a0
}

        
