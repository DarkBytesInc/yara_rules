rule Win_Spyware_Banker_657
{
strings:
	$a0 = { 587eb08c93812f6508c3476896a312f3af99b6bcbdb4acb876bee49ed97dd0ba18b59509be53c8c3c5a7e7b86aa45b8ecbcd2782710bf3a42247aa2a5b031222452a4a2ee1b996b860ed71220dae913a9f4587f87ea5fad6f02b1cfc1d41dd3bf86db50a53c58cb6783f5bd5a6dbebaa0c8d3d96daa1cbed1da64edbaf }

condition:
	$a0
}

        
