rule Win_Spyware_159_2
{
strings:
	$a0 = { 5a1a749046d5099d65bfbf57304b9378b91edb65e2be0f8ec46b6ea5ca7e11687e2a1c0c49b22f0dc7f758862038463c8a7ca362ad56ebecddc547e74f4260a61a8f56cfcf861851be6acc0a57d4e9374e9e5ad28afd171902657b4f8eee }

condition:
	$a0
}

        
