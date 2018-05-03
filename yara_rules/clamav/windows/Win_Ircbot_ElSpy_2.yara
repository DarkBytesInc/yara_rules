rule Win_Ircbot_ElSpy_2
{
strings:
	$a0 = { 32dea77427af4bbf46f5ff459afe14f5bfdfbabcb7b0dfb0b9b932dea77427af4bbf46fdff4580fe }

condition:
	$a0
}

        
