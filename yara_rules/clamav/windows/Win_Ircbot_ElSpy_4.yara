rule Win_Ircbot_ElSpy_4
{
strings:
	$a0 = { 32de4bc3cc3645b6fe14f59c908f8687d19d9e8bff32deafa77427af4bbf46fdff459bfe14fdf2f5 }

condition:
	$a0
}

        
