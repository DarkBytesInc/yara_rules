rule Win_Worm_Bobax_50
{
strings:
	$a0 = { 6e363ce8047f2653ba94dd9b6cfcde4482649bc92c570238d6ece7940fab1354f6168e808984ea07e7ebee2f96e1db1291965b7334111fe1c4b4816510988771406e4c070ac78a7895dd81e79c84750dc02c72334aba3c628e80f80eb0dd3e586bd7cea0c28cbc6134287ef5c494684fb23cf6027de30a7a5f1ee39267983b056ce6fbf57614992dd14de90e833658c5f81e54bee9d6 }

condition:
	$a0
}

        