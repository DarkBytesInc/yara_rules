rule Win_Spyware_405_2
{
strings:
	$a0 = { 7683f19ea0451927b511271d2ae5415853916fd591cec85523902ab7d20bd972a9bc08d2822af8bcf0c96b016c7d8fcae5724ece02366d95b4aac45fd9d422b0f73d0dc8ee2b4ccbe88f8615e055 }

condition:
	$a0
}

        
