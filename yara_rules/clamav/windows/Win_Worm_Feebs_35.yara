rule Win_Worm_Feebs_35
{
strings:
	$a0 = { 16794bfd132d8cb04a41204d8ca04db76fc00a7496de78d863fba2edeab3a514ca889ed00bb518738f5b066983493ef93886c00035024c0aebc5f3a296a4284bf3075dbafcd7f54a5ab716d7eaf81e9a8d58d036e74ec73d5f4eb61c01c8b05a }

condition:
	$a0
}

        
