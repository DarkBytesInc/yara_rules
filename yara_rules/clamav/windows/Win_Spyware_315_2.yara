rule Win_Spyware_315_2
{
strings:
	$a0 = { 131a9fcedc6f82a5b137b0e7a8b93667e8db81541729109a68bb65e7ca9fbd13f90cbf1c9214ec07c2acdf77a570a49ca2fc2ea4aebcce7f034c7990b14581a65ccbf6e153b0dec94680417de82711de818a93ce2b16f880ab0ae6e35caacc }

condition:
	$a0
}

        
