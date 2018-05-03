rule Win_Tool_Epr_1
{
strings:
	$a0 = { 46f70d202020203d6f72657261c3b800000000ffe0b800000000ffe0e8000000005d81ed8e000000c3565755e8ebffffff }

condition:
	$a0
}

        
