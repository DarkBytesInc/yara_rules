rule Win_Spyware_Delf_503
{
strings:
	$a0 = { 9abd0d5c5455fa387e67e602038e0e28be6b928d29a205a2250ee6280ee20b3a8220bea0594a68a62edcab5620c35ed8bc9ca6d8ddda6d7fb6bbb9d6d69adf8db24db436074641b22dc552144b53ab8bd70a959551c8f93fcfb96786d15cadbf1f87e7dc73cef39ce73ce739cf79ceb9e79ccb47da3843d894b56b57af }

condition:
	$a0
}

        
