rule Win_Trojan_Spambot_133
{
strings:
	$a0 = { c0f91e0f3cffffffffd01a04c09717e192de4f215999b9582d8a35608de30482224efd1e8d317bb15dffffffff96cfe4cf9d20a41984cfd36246298c7b0b56d3a1fa9eb0b4049fc4ad7125407cfffffffff59e558607db6fc088e41683ada1cd5145053cc42c41c7de3ff0cd5a3b }

condition:
	$a0
}

        
