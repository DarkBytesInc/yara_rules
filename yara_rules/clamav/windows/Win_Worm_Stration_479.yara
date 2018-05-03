rule Win_Worm_Stration_479
{
strings:
	$a0 = { 6fc3e6361fb3a4e520b368eb65646a21cc486ff98e6c3da6ae504e6dda1a4319a99025bb6a8733d5966bcc0db0acc3c4b7baed726b0e37e0f84b1facd9e0440b9247d555846bd45e1bd3665c3240b34ecee82d83f097a0c09b85c2baf2da5e54868e8d7563 }

condition:
	$a0
}

        
