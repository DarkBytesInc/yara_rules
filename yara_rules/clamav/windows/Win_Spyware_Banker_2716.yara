rule Win_Spyware_Banker_2716
{
strings:
	$a0 = { 0f25528e342947690594379932334a18e79fdf7be7c10834d9e596d06b07809c54d4881f12eaf67872f72b4b33b502cc77e2bd5f7dc10733c820 }

condition:
	$a0
}

        
