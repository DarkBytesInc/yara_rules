rule Win_Spyware_744_2
{
strings:
	$a0 = { 59a6d2094a0f3a4c29b7ea74040c03743f969da538e5b7c9b95167458ccc3ee74503bc5d08728809dcdbfe1fac541c0f050fe98f0cafe193403beaaf8f0eca183a1c2a7746a0838b755c61f835bb1f18db8b3af23a7277e04eda }

condition:
	$a0
}

        
