rule Win_Tool_AnsiBomb_6
{
strings:
	$a0 = { b430cd213c027302cd20bf43098b3602002bf781fe00107203be0010fa8ed781c4fe0afb730b33c036c706100ac102eb }

condition:
	$a0
}

        
