rule Unix_Tool_13355_1
{
strings:
	$a0 = { 6a6658996a015b52536a0289e1cd805b5e68efbeaddebdfdffffaff7d555436a105150b06689e1cd805fb008526a4189e35059cd809687df }
	$a1 = { cd8087de72f785c07405b004f9ebf1b006cd8099b00b89fb5253ebcc }

condition:
	$a0 and $a1
}

        
