rule Win_Trojan_Ciadoor_202
{
strings:
	$a0 = { 297a7d3dc530c73e3e6dc536c73e3eaa60c96d4b3d453e2e1e3dc59ec73e3eaad545197a7d3d45097a7d3dc54fc73e3e6dc54dc73e3ea4608d45797a7d3d45697a7d3dc557c73e3e6dc555c73e3ea460f145517a7d3d45097a7d3dc57fc73e3e6dc57dc7 }

condition:
	$a0
}

        
