rule Win_Spyware_Banker_3364
{
strings:
	$a0 = { 6dfef5dc78370972665ced9ae7e0020aebf197f7dfd010665f063f8570c7fabb02df2b20a1a1700dbb1dc2ce89aa655dd2a6c6ac712e01072a8769e99f83bcac13e42f2bfc47344b23eb3cd20b8cfe52171c96a2f4 }

condition:
	$a0
}

        
