rule Win_Worm_VB_821
{
strings:
	$a0 = { 6600740020005300500034002c004100630072006f0062006100740020005200650061006400650072002c00530065007400750070002c004e004100490020004d00630061006600650065002c004e006f00720074006f006e002000410056002c00500047005000200046007200650065002c00500061007300730077006f007200640020007200650063006f007600650072007900 }

condition:
	$a0
}

        