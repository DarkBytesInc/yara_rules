rule Win_Dropper_Agent_33966
{
strings:
	$a0 = { fe8bfa13f50db5bc28a36851517e91bec852642de28bfa8ab2344b346b34eb354d9a47343b35bfd64c683ed3246b576a0dda0dda46ed566dbbd6af7d4cdba3fdb6b65ffb2bed49ed59ed07da0fb597b537b40a5d }

condition:
	$a0
}

        
