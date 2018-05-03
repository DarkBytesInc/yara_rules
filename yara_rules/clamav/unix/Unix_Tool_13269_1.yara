rule Unix_Tool_13269_1
{
strings:
	$a0 = { 31d2eb0e31db5bb119832c1a0142e2f9eb05e8edffffff32c15169303074696930636a6f32dc8ae451555451b13cce81 }

condition:
	$a0
}

        
