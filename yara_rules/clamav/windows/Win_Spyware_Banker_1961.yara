rule Win_Spyware_Banker_1961
{
strings:
	$a0 = { 5fe87cdb46eedd8b07c675efa5feb707fda198696abcb26b3e2a90e0783360f5dbd1a24b6a70e4d3b9dea0a06fcc93f64a82b62ba401a3ec4be91c7955a992e37bb1117a538ca2c2dba172a8487132f29d3628f9fcee97acd2cf4e2dd783e945bb00db66c4c3fd1178bee87f05d8b4d60b967c504e0cc4becf2fb90e54c087a0 }

condition:
	$a0
}

        
